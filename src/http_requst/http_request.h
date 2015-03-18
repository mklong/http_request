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
#include <string.h>

namespace http
{

	/** 
	* @class	http_request
	* 
	* @brief	
	*	
	*		�����ܰ��http���������
	*		��Ҫ�������ڴ��ʹ����
	*
	* detail...
	*	��Ҫ��;�����¼���
	*	1.��������ܽ������ݣ�Ϊhttp�������ṩ�ڴ����ͽ�������
	*	2.��������ܷ������ݣ�Ϊhttp�����ṩ�ڴ����ʹ������
	*
	* @author	 mklong
	* @date	2014/11/12
	* 
	* @see		
	* 
	* @par ��ע��
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
			START = 0,				//��δ������ͷ��
			HEADER_FIELD,			//ͷ��������
			HEADER_VALUE,			//ͷ��������
			HEADER_DONE,			//����ͷ������Ҫ���س���
			BODY,						//�ȴ�body��������
			DONE,						//��������
			ERROR						//��������
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
			MAX_BODY_SIZE = 1024*1024,

		};

		typedef void (*cleanup_pt)(void *data);
		static void default_cleanup(void *data);

		/** 
		* @brief 	*create_http_request
		* 
		* 	�����ڴ�أ������ڴ���з���˶��󣬳�ʼ����ز���
		* 
		* @author	mklong
		* @date	2014/11/12
		* @return	static http_request ��return NULL if failed
		* @see		
		*/
		static http_request *create_http_request();


		/** 
		* @brief 	finalize_http_request
		* 
		* 	�ͷ��ڴ�أ�

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
		* 	���request��Ҫ��������Ҫ��ʼ��������
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
		* 	����http��������
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
		* 	��ȡhttp���������еľ������ԭ��
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
		* 	���������ṩ�ڴ������������ڴ�ط���
		* ÿ�ε��ã��ϵ�buf����ص�recv_chain��
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
		* 	��ȡ�����ͷ
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
		* 	��ȡhttp method
		* 
		* @author	mklong
		* @date	2014/11/20
		* @return	const char 
		* @see		
		*/
		const char *get_method();


		/** 
		* @brief 	get_http_version
		* 
		* 	��ȡhttp�汾��
		* 
		* @author	mklong
		* @date	2014/11/20
		* @return	size_t 
		* @see		
		*/
		size_t get_http_version();



		/** 
		* @brief 	set_out_first_line
		* 
		* 	��Ϊout requestʱ��reqeust line
		* ����responseʱ��status line
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
		* 	������Ӧͷ
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

		/** 
		* @brief 	add_out_body
		* 
		* 	����body��@cleanΪ@body���ͷź���
		*	���δ�����ڲ��´��@body
		*  ���ú��ڲ���ӹ�@body���ͷţ��ͷź���Ϊ@clean
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

		/** 
		* @brief 	package_request
		* 
		* 	�������õ�out��Ϣ���http��Ӧ��send_chain��
		* 
		* @author	mklong
		* @date	2014/11/17
		* @return	int	- Return 0 in success, otherwise return error code.
		* @see		
		*/
		int package_request();


		/** 
		* @brief 	set_max_header_size
		* 
		* 	����http��������ͷ�������ͷ��������ֵ��ʧ��
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
		* 	����http��������body�����������ֵ��ʧ��
		* 
		* @author	mklong
		* @date	2014/11/18
		* @return	No return value.
		* @param	size_t size	- [in] 
		* @see		
		*/
		void set_max_body_size(size_t size); 

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

	public:
		//�ڴ��
		ngx_pool_t *pool;

		//////////////////////////////////////////////////////////////////////////
		// request in variable
		//////////////////////////////////////////////////////////////////////////

		//response only
		ngx_str_t status;

		//request only
		ngx_str_t uri;

		//
		int content_length;

		//ngx_table_elt_t ��ʱָ��
		ngx_table_elt_t * header_last;
		ngx_list_t *headers_in;


		//������ʱ������,��ʼ��ʱ����ҳ��С�ڴ棬buf��������£�
		//����alloc_recv_buf���buf���ص�recv_chain�ϣ������·���
		ngx_buf_t *buf;	

		//body���ݣ���������ڴ棬ֱ��ָ��bufλ��
		ngx_chain_t body;	

		//����������
		ngx_chain_t recv_chain; 

		//////////////////////////////////////////////////////////////////////////
		// request out variable
		//////////////////////////////////////////////////////////////////////////

		//out
		ngx_str_t out_first_line;

		ngx_list_t *headers_out;

		//����body��
		ngx_chain_t body_out_chain;

		//������
		ngx_chain_t send_chain;   

		//////////////////////////////////////////////////////////////////////////
		//	others
		//////////////////////////////////////////////////////////////////////////

		//request��ָ��
		http_request *next;

		void *	reserved;

		//���ò��������ص�
		http_parser_settings setting; 

		//http������
		http_parser parser;   

		//����״̬
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
		//parser �ص�����ĳ��ֵ���ֶܷ�Σ����ܷ�������buffer�У���Ҫ�ж��Ƿ�����
		if (str->data != NULL ){

			if (str->data + str->len == data){
				str->len += length;
				return 0;
			}else{
				//����Ԥ�����ڴ�״̬������Թ����ҿ�buffer���������������Σ�
				//�ʲ���ÿ�η������
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

	inline const char * http_request::get_method()
	{
		return http_method_str((http_method)this->parser.method);
	}

	inline const char * http_request::parser_errno()
	{
		return http_errno_description(HTTP_PARSER_ERRNO(&parser));
	}

	inline size_t http_request::get_http_version()
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

}

#endif /* __HTTP_REQUEST_H__ */
