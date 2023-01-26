#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>


#define DNS_SVR  "114.114.114.114"

#define DNS_HOST  0x01
#define DNS_CNAME 0x05

#define ASYNC_CLIENT_NUM 1024

//封装的dns协议头
struct dns_header{
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};


//DNS请求
struct dns_question{
    int length;
    unsigned short qtype;
    unsigned short qclass;
    char* qname;
};

//对DNS服务器返回的响应解析之后，得到的结果
struct dns_item{
   char* domain;  //域名
   char* ip;      //IP
};

typedef void (* async_result_cb)(struct dns_item* list,int count);

struct async_context{
    int epfd;
    pthread_t thread_id;
};

struct ep_arg{
    int sockfd;
    async_result_cb cb;
};



int dns_create_header(struct dns_header* header){
    if(header == NULL){
        return -1;
    }

    memset(header,0,sizeof(struct dns_header));
    srandom(time(NULL));    //相当于添加随机数种子


    header->id = random();
    header->flags |= htons(0x100);
    header->qdcount = htons(1);

    return 0;
}

int dns_create_question(struct dns_question* question,const char* hostname){
    if(question == NULL){
        return -1;
    }

    memset(question,0,sizeof(struct dns_question));
    question->qname = (char*)malloc(strlen(hostname) + 2);
    if(question->qname == NULL){
        return -2;
    }

    question->length = strlen(hostname) + 2;

    question->qtype = htons(1);
    question->qclass = htons(1);

    const char delim[2] = ".";

    //strdup是拷贝字符串的函数
    char* hostname_dup = strdup(hostname);

    char* token = strtok(hostname_dup,delim);

    char* qname_p = question->qname;

    while(token != NULL){
        size_t len = strlen(token);

        *qname_p = len;
        qname_p++;

        strncpy(qname_p,token,len + 1);
        qname_p += len;

        token = strtok(NULL,delim);
    }

    free(hostname_dup);

    return 0;
}

int dns_build_request(struct dns_header* header,struct dns_question* question,char* request){
    int header_s = sizeof(struct dns_header);
    int question_s = question->length + sizeof(question->qtype) + sizeof(question->qclass);

    int length = header_s + question_s;

    int offset = 0;
    memcpy(request + offset,header,sizeof(struct dns_header));
    offset += sizeof(struct dns_header);

    memcpy(request + offset,question->qname,question->length);
    offset += question->length;

    memcpy(request + offset,&question->qtype,sizeof(question->qtype));
    offset += sizeof(question->qtype);

    memcpy(request + offset,&question->qclass,sizeof(question->qclass));

    return length;
}

static int is_pointer(int in){
    return ((in & 0xC0) == 0xC0);
}

//block != 0,设置阻塞
//block == 0 ,设置非阻塞
static int set_block(int fd,int block){
    int flags = fcntl(fd,F_GETFL,0);
    if(flags < 0){
        return flags;
    }

    if(block){
        flags &= ~O_NONBLOCK;
    }else{
        flags |= O_NONBLOCK;
    }
    if(fcntl(fd,F_SETFL,flags) < 0){
        return -1;
    }

    return 0;
}

//解析返回的名称
static void dns_parse_name(unsigned char* chunk,unsigned char*  ptr,char* out,int* len){
    int flag = 0;
    int n = 0;
    int alen = 0;

    char* pos = out + (*len);
    while(1){
        flag = (int)ptr[0];
        if(flag == 0){
            break;
        }

        if(is_pointer(flag)){
            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_name(chunk,ptr,out,len);
            break;
        }else{
            ptr++;
            memcpy(pos,ptr,flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if((int)ptr[0] != 0){
                memcpy(pos,".",1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}

//解析收到的dns服务器返回的结果，然后返回一个dns_item数组
static int dns_parse_response(char* buffer,struct dns_item** domains){
    int i = 0;
	unsigned char *ptr = buffer;

	ptr += 4;
	int querys = ntohs(*(unsigned short*)ptr);

	ptr += 2;
	int answers = ntohs(*(unsigned short*)ptr);

	ptr += 6;
	for (i = 0;i < querys;i ++) {
		while (1) {
			int flag = (int)ptr[0];
			ptr += (flag + 1);

			if (flag == 0) break;
		}
		ptr += 4;
	}

	char cname[128], aname[128], ip[20], netip[4];
	int len, type, ttl, datalen;

	int cnt = 0;
	struct dns_item *list = (struct dns_item*)calloc(answers, sizeof(struct dns_item));
	if (list == NULL) {
		return -1;
	}

	for (i = 0;i < answers;i ++) {
		
		bzero(aname, sizeof(aname));
		len = 0;

		dns_parse_name(buffer, ptr, aname, &len);
		ptr += 2;

		type = htons(*(unsigned short*)ptr);
		ptr += 4;

		ttl = htons(*(unsigned short*)ptr);
		ptr += 4;

		datalen = ntohs(*(unsigned short*)ptr);
		ptr += 2;

		if (type == DNS_CNAME) {

			bzero(cname, sizeof(cname));
			len = 0;
			dns_parse_name(buffer, ptr, cname, &len);
			ptr += datalen;
			
		} else if (type == DNS_HOST) {

			bzero(ip, sizeof(ip));

			if (datalen == 4) {
				memcpy(netip, ptr, datalen);
				inet_ntop(AF_INET , netip , ip , sizeof(struct sockaddr));

				printf("%s has address %s\n" , aname, ip);
				printf("\tTime to live: %d minutes , %d seconds\n", ttl / 60, ttl % 60);

				list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
				memcpy(list[cnt].domain, aname, strlen(aname));
				
				list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
				memcpy(list[cnt].ip, ip, strlen(ip));
				
				cnt ++;
			}
			
			ptr += datalen;
		}
	}

	*domains = list;
	ptr += 2;

	return cnt;
}

void dns_async_client_free_domains(struct dns_item* list,int count){
    int i = 0;
    for(;i < count;++i){
        free(list[i].domain);
        free(list[i].ip);
    }
    free(list);
}

//下面就是异步请求池的四大操作

//初始化的时候，创建的专门用来接收数据的线程的工作函数
static void* dns_async_client_proc(void* arg){
    struct async_context* ctx = (struct async_context*)arg;
    int epfd = ctx->epfd;

    while(1){
        struct epoll_event events[ASYNC_CLIENT_NUM] = {0};
        int nready = epoll_wait(epfd,events,ASYNC_CLIENT_NUM,-1);
        if(nready < 0){
            if(errno == EINTR || errno == EAGAIN){
                continue;
            }else{
                break;
            }
        }else if(nready == 0){
            continue;
        }

        printf("nready:%d\n",nready);

        int i = 0;
        for(;i < nready;++i){
            struct ep_arg* data = (struct ep_arg*)events[i].data.ptr;
            int sockfd = data->sockfd;

            char buffer[1024] = {0};
            struct sockaddr_in addr;
            size_t addr_len = sizeof(struct sockaddr_in);

            int n = recvfrom(sockfd,buffer,sizeof(buffer),0,(struct sockaddr*)&addr,(socklen_t*)&addr_len);

            struct dns_item* domain_list = NULL;
            int count = dns_parse_response(buffer,&domain_list);

            data->cb(domain_list,count);

            int ret = epoll_ctl(epfd,EPOLL_CTL_DEL,sockfd,NULL);

            close(sockfd);
            dns_async_client_free_domains(domain_list,count);
            free(data);
        }
    }
}

int dns_async_client_commit(struct async_context* ctx,const char* domain,async_result_cb cb){
    int sockfd = socket(PF_INET,SOCK_DGRAM,0);
    if(sockfd < 0){
        perror("create udp socket failed\n");
        exit(-1);
    }

    printf("url:%s\n",domain);

    set_block(sockfd,0);//设置非阻塞


    struct sockaddr_in dest;
    bzero(&dest,sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(DNS_SVR);
    dest.sin_port = htons(53);

    //1.建立连接
    int ret = connect(sockfd,(struct sockaddr*)&dest,sizeof(dest));
    if(ret < 0){
        perror("udp connect error\n");
        exit(-1);
    }

    //2.封装协议
    struct dns_header header = {0};
    dns_create_header(&header);

    struct dns_question question = {0};
    dns_create_question(&question,domain);

    char request[1024] = {0};
    int req_len = dns_build_request(&header,&question,request);

    //3.发送请求
    int slen = sendto(sockfd,request,req_len,0,(struct sockaddr*)&dest,sizeof(struct sockaddr));

    //4.加入epoll管理fd，并且注册读事件
    struct ep_arg* eparg = (struct ep_arg*)calloc(1,sizeof(struct ep_arg));
    if(eparg == NULL){
        return -1;
    }
    eparg->sockfd = sockfd;
    eparg->cb = cb;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = eparg;

    ret = epoll_ctl(ctx->epfd,EPOLL_CTL_ADD,sockfd,&ev);

    return ret;
}

//初始化函数
struct async_context* dns_async_client_init(){
    int epfd = epoll_create(1);
    if(epfd < 0){
        return NULL;
    }

    struct async_context* ctx = calloc(1,sizeof(struct async_context));
    if(ctx == NULL){
        close(epfd);
        return NULL;
    }

    ctx->epfd = epfd;

    //创建专门用来接收服务器返回数据的线程
    int ret = pthread_create(&ctx->thread_id,NULL,dns_async_client_proc,(void*)ctx);
    if(ret){
        perror("pthread_create failed\n");
        return NULL;
    }
    usleep(1);

    return ctx;
}

void dns_async_client_destroy(struct async_context* ctx){
    close(ctx->epfd);
    pthread_cancel(ctx->thread_id);
}

//连接收到服务器返回的数据，并且解析完成之后，会调用的回调函数
static void dns_async_client_result_callback(struct dns_item* list,int count){
    int i = 0;
    for(;i < count;++i){
        printf("name:%s,ip:%s\n",list[i].domain,list[i].ip);
    }
}

char *domain[] = {
	"www.ntytcp.com",
	"bojing.wang",
	"www.baidu.com",
	"tieba.baidu.com",
	"news.baidu.com",
	"zhidao.baidu.com",
	"music.baidu.com",
	"image.baidu.com",
	"v.baidu.com",
	"map.baidu.com",
	"baijiahao.baidu.com",
	"xueshu.baidu.com",
	"cloud.baidu.com",
	"www.163.com",
	"open.163.com",
	"auto.163.com",
	"gov.163.com",
	"money.163.com",
	"sports.163.com",
	"tech.163.com",
	"edu.163.com",
	"www.taobao.com",
	"q.taobao.com",
	"sf.taobao.com",
	"yun.taobao.com",
	"baoxian.taobao.com",
	"www.tmall.com",
	"suning.tmall.com",
	"www.tencent.com",
	"www.qq.com",
	"www.aliyun.com",
	"www.ctrip.com",
	"hotels.ctrip.com",
	"hotels.ctrip.com",
	"vacations.ctrip.com",
	"flights.ctrip.com",
	"trains.ctrip.com",
	"bus.ctrip.com",
	"car.ctrip.com",
	"piao.ctrip.com",
	"tuan.ctrip.com",
	"you.ctrip.com",
	"g.ctrip.com",
	"lipin.ctrip.com",
	"ct.ctrip.com"
};

int main(int argc,char** argv){
    struct async_context* ctx = dns_async_client_init();
    if(ctx == NULL){
        return -2;
    }

    //一共多少个域名
    int count = sizeof(domain) / sizeof(domain[0]);
    int i = 0;
    for(;i < count;++i){
        dns_async_client_commit(ctx,domain[i],dns_async_client_result_callback);
    }
    getchar();

    dns_async_client_destroy(ctx);

    return 0;
}



