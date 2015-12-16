/** 
* @file	http_request.h
* @brief	
*		
* detail...
*		
*
* @author	mklong
* @version	1.0
* @date	2014/11/12
* 
* @see		
* 
* <b>History:</b><br>
* <table>
*  <tr> <th>Version	<th>Date		<th>Author	<th>Notes</tr>
*  <tr> <td>1.0		<td>2014/11/12	<td>mklong	<td>Create this file</tr>
* </table>
* 
*/
#ifndef __HTTP_REQUEST_H__
#define __HTTP_REQUEST_H__

#include "openlib/nginx/libngx.h"
#include "openlib/http_parser/http_parser.h"

namespace http
{

	/** 
	* @class	http_request
	* 
	* @brief	
	*	
	*		高性能版的http打包,解析库
	*		主要体现在内存的使用上
	*
	* detail...
	*	主要用途有以下几点
	*	1.配合网络框架接收数据，为http数据流提供内存分配和解析功能
	*	2.配合网络框架发送数据，为http数据提供内存分配和打包功能
	*
	* @author	 mklong
	* @date	2014/11/12
	* 
	* @see		
	* 
	* @par 备注：
	* 
	*/
	struct  http_request
	{
		enum HTTP_VERSION{
			HTTP_VERSION_9 = 9,			//HTTP/0.9
			HTTP_VERSION_10 = 1000,		//HTTP/1.0
			HTTP_VERSION_11 = 1001,		//HTTP/1.1
			HTTP_VERSION_20 = 2000,		//HTTP/2.0
		};

		enum PARSE_STATE{
			START = 0,				//尚未解析过头部
			HEADER_FIELD,			//头部解析中
			HEADER_VALUE,			//头部解析中
			HEADER_DONE,			//解析头部，主要返回长度
			BODY,						//等待body部分数据
			DONE,						//数据完整
			ERROR						//解析出错
		};

		enum PARSER_TYPE {
			HTTP_REQUEST = 0,
			HTTP_RESPONSE,
			HTTP_BOTH,
		};

		enum{
			ALLOC_STR_SIZE = 64,
			ALLOC_PAGESIZE = 4096,
			MAX_HEADER_SIZE = 4096,
			MAX_BODY_SIZE = 10*1024*1024,

		};

		typedef void (*cleanup_pt)(void *data);
		static void default_cleanup(void *data);

		/** 
		* @brief 	*create_http_request
		* 
		* 	分配内存池，并在内存池中分配此对象，初始化相关参数
		* 
		* @author	mklong
		* @date	2014/11/12
		* @return	static http_request ，return NULL if failed
		* @see		
		*/
		static http_request *create_http_request();


		/** 
		* @brief 	finalize_http_request
		* 
		* 	释放内存池，

		* 
		* @author	mklong
		* @date	2014/11/12
		* @return	No return value.
		* @param	http_request* r	- [in] 
		* @see		
		*/
		static void finalize_http_request(http_request* r);


		/** 
		* @brief 	init_request_parser
		* 
		* 	如果request需要解析，需要初始化解析器
		* 
		* @author	mklong
		* @date	2014/11/18
		* @return	int	- Return 0 in success, otherwise return error code.
		* @param	PARSER_TYPE type = PARSER_TYPE::HTTP_REQUEST	- [in] 
		* @param	size_t default_recv_buf = ALLOC_PAGESIZE	- [in] pre alloc recv buf size
		* @see		
		*/
		int init_request_parser(PARSER_TYPE type = HTTP_BOTH,
								size_t default_recv_buf = ALLOC_PAGESIZE);


		/** 
		* @brief 	run_http_parser
		* 
		* 	调用http解析函数
		* 
		* @author	mklong
		* @date	2014/11/12
		* @return	int	- Return >0 in success, otherwise return error code.
		* @param	const char *data	- [in] 
		* @param	size_t len	- [in] 
		* @param	bool *done	- [in] whether http request parse completed
		* @see		
		*/
		int run_http_parser(const char *data,size_t len,bool *done);


		/** 
		* @brief 	* parser_errno
		* 
		* 	获取http解析过程中的具体错误原因
		* 
		* @author	mklong
		* @date	2014/11/12
		* @return	const char 
		* @see		
		*/
		const char * parser_errno();


		/** 
		* @brief 	alloc_recv_buf
		* 
		* 	接收数据提供内存分配操作，从内存池分配
		* 每次调用，老的buf会挂载到recv_chain上
		*
		* @author	mklong
		* @date	2014/11/12
		* @return	int	- Return 0 in success, otherwise return error code.
		* @param	size_t size = ALLOC_PAGESIZE	- [in] 
		* @see		
		*/

		int alloc_recv_buf(size_t size = ALLOC_PAGESIZE);


		/** 
		* @brief 	*get_in_header
		* 
		* 	获取请求的头
		* 
		* @author	mklong
		* @date	2014/11/17
		* @return	const char 
		* @param	const char * field	- [in] 
		* @see		
		*/
		const ngx_str_t *get_in_header(const char * field,size_t len);
		const ngx_str_t *get_in_header(const char * field);


		/** 
		* @brief 	*get_method
		* 
		* 	获取http method
		* 
		* @author	mklong
		* @date	2014/11/20
		* @return	const char 
		* @see		
		*/
		const char *get_method() const;


		/** 
		* @brief 	get_http_version
		* 
		* 	获取http版本号
		* 
		* @author	mklong
		* @date	2014/11/20
		* @return	size_t 
		* @see		
		*/
		size_t get_http_version() const;

		int copy_out_first_line_from_in();

		/** 
		* @brief 	set_out_first_line
		* 
		* 	作为out request时的reqeust line
		* 或者response时的status line
		* 
		* @author	mklong
		* @date	2014/11/21
		* @return	int	- Return 0 in success, otherwise return error code.
		* @param	const char * line	- [in] 
		* @see		
		*/

		int set_out_first_line(const char * line);
		int set_out_first_line(const char * line,size_t len);

		/** 
		* @brief 	add_out_header
		* 
		* 	设置响应头
		* 
		* @author	mklong
		* @date	2014/11/17
		* @return	int	- Return 0 in success, otherwise return error code.
		* @param	const char * field	- [in] 
		* @param	const char * value	- [in] 
		* @see		
		*/
		int add_out_header(const char * field ,const char * value);
		int add_out_header( const char * field , size_t field_len,
							const char * value , size_t value_len);

		int copy_out_headers_from_in();

		/** 
		* @brief 	add_out_body
		* 
		* 	设置body，@clean为@body的释放函数
		*	如果未设置内部会拷贝@body
		*  设置后，内部会接管@body的释放，释放函数为@clean
		*
		* @author	mklong
		* @date	2014/11/21
		* @return	int	- Return 0 in success, otherwise return error code.
		* @param	const char * body	- [in] 
		* @param	size_t length	- [in] 
		* @param	cleanup_pt clean = NULL	- [in] 
		* @see		
		*/
		int add_out_body(const char * body,size_t length,cleanup_pt clean = NULL);

		int copy_out_body_from_in();

		/** 
		* @brief 	package_request
		* 
		* 	根据设置的out信息打包http响应到send_chain中
		* 
		* @author	mklong
		* @date	2014/11/17
		* @return	int	- Return 0 in success, otherwise return error code.
		* @see		
		*/
		int package_request();

		int copy_out_request_from_in();

		/** 
		* @brief 	set_max_header_size
		* 
		* 	设置http解析最大的头部，如果头部超过阀值则失败
		* 
		* @author	mklong
		* @date	2014/11/18
		* @return	No return value.
		* @param	size_t size	- [in] 
		* @see		
		*/
		void set_max_header_size(size_t size);


		/** 
		* @brief 	set_max_body_size
		* 
		* 	设置http解析最大的body，如果超过阀值则失败
		* 
		* @author	mklong
		* @date	2014/11/18
		* @return	No return value.
		* @param	size_t size	- [in] 
		* @see		
		*/
		void set_max_body_size(size_t size);

		void reset_chain_buf();
	private:
		// http parser callback
		//event callback
		static int http_header_start_cb(http_parser*);
		static int http_header_done_cb(http_parser*);
		static int http_message_done_cb(http_parser*);

		//data callback
		static int http_url_cb (http_parser*, const char *at, size_t length);
		static int http_status_cb (http_parser*, const char *at, size_t length);
		static int http_header_field_cb (http_parser*, const char *at, size_t length);
		static int http_header_value_cb (http_parser*, const char *at, size_t length);
		static int http_body_cb (http_parser*, const char *at, size_t length);

		int set_parse_str(ngx_str_t * str, u_char* data, size_t length);
		int ngx_str_alloc_cpy(ngx_str_t * str,const u_char * data , size_t len);
		void reset_chain_buf_pos(ngx_chain_t * chain);
	public:
		//内存池
		ngx_pool_t *pool;

		//////////////////////////////////////////////////////////////////////////
		// request in variable
		//////////////////////////////////////////////////////////////////////////

		//request first line
		ngx_str_t in_first_line;

		//response only
		ngx_str_t status;

		//request only
		ngx_str_t uri;
		ngx_str_t args;

		//
		int content_length;

		//ngx_table_elt_t 临时指针
		ngx_table_elt_t * header_last;
		ngx_list_t *headers_in;


		//接收临时缓冲区,初始化时分配页大小内存，buf满的情况下，
		//调用alloc_recv_buf会把buf挂载到recv_chain上，并重新分配
		ngx_buf_t *buf;

		//body数据，无需分配内存，直接指向buf位置
		ngx_chain_t body;

		//接收数据链
		ngx_chain_t recv_chain;

		//////////////////////////////////////////////////////////////////////////
		// request out variable
		//////////////////////////////////////////////////////////////////////////

		//out
		ngx_str_t out_first_line;

		ngx_list_t *headers_out;

		//发送body链
		ngx_chain_t body_out_chain;

		//发送链
		ngx_chain_t send_chain;

		//////////////////////////////////////////////////////////////////////////
		//	others
		//////////////////////////////////////////////////////////////////////////

		//request链指针
		http_request *next;

		void *	reserved;

		//设置参数解析回调
		http_parser_settings setting;

		//http解析器
		http_parser parser;

		//解析状态
		short state;

		//
		size_t max_header_size;

		//
		size_t max_body_size;


	};


	//inline func

	inline const ngx_str_t * http_request::get_in_header( const char * field )
	{
		return get_in_header(field,strlen(field));
	}

	inline int http_request::add_out_header(const char * field ,const char * value)
	{
		return add_out_header(field,strlen(field),value,strlen(value));
	}

	inline void http_request::set_max_header_size( size_t size )
	{
		this->max_header_size = size;
	}

	inline void http_request::set_max_body_size( size_t size )
	{
		this->max_body_size = size;
	}

	inline int http_request::set_parse_str( ngx_str_t * str, u_char* data, size_t length )
	{
		//parser 回调设置某个值可能分多次，可能分在两个buffer中，需要判断是否连续
		if (str->data != NULL ){

			if (str->data + str->len == data){
				str->len += length;
				return 0;
			}else{
				//由于预分配内存状态标记难以管理，且跨buffer的情况不会连续多次，
				//故采用每次分配策略
				u_char * buf = (u_char *)ngx_palloc(this->pool,str->len + length);
				if (buf == NULL){
					return -1;
				}

				ngx_memcpy(buf, str->data, str->len);
				ngx_memcpy(buf + str->len, data, length);
				str->data = buf;
				str->len += length;
				return 0;
			}

		}else{
			str->data = data;
			str->len = length;
		}

		return 0;
	}

	inline const char * http_request::get_method() const
	{
		return http_method_str((http_method)this->parser.method);
	}

	inline const char * http_request::parser_errno()
	{
		return http_errno_description(HTTP_PARSER_ERRNO(&parser));
	}

	inline size_t http_request::get_http_version() const
	{
		return this->parser.http_major *1000 +this->parser.http_minor;
	}

	inline int http_request::set_out_first_line( const char * line )
	{
		return set_out_first_line(line,strlen(line));
	}

	inline int http_request::ngx_str_alloc_cpy(ngx_str_t * str, const u_char * data , size_t len )
	{
		str->data = (u_char*)ngx_palloc(this->pool,len);
		if (str->data  == NULL){
			return -1;
		}

		ngx_memcpy(str->data,data,len);
		str->len = len;
		return 0;
	}

	inline void http_request::reset_chain_buf_pos(ngx_chain_t * chain)
	{
		while(chain){
			if (chain->buf){
				chain->buf->pos = chain->buf->start;
			}

			chain = chain->next;
		}
	}

}

#endif /* __HTTP_REQUEST_H__ */
