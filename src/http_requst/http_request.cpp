#include "http_request.h"

namespace http
{


	http_request * http_request::create_http_request()
	{
		//��ʼ���ڴ��
		ngx_pool_t *p = ngx_create_pool(ALLOC_PAGESIZE);
		if (p == NULL){
			return NULL;
		}

		http_request *r = (http_request*)ngx_pcalloc(p, sizeof(http_request));
		if (r == NULL) {
			ngx_destroy_pool(p);
			return NULL;
		}

		r->pool = p;

		r->max_header_size = MAX_HEADER_SIZE;
		r->max_body_size = MAX_BODY_SIZE;

		return r;
	}

	void http_request::finalize_http_request( http_request* r )
	{
		ngx_destroy_pool(r->pool);
	}

	int http_request::init_request_parser( PARSER_TYPE type /*= PARSER_TYPE::HTTP_REQUEST*/ 
		,size_t default_recv_buf /*= ALLOC_PAGESIZE*/)
	{
		//init parser
		this->parser.data = this;
		http_parser_init(&this->parser,(http_parser_type)type);

		//init  setting
		this->setting.on_message_begin = http_header_start_cb;
		this->setting.on_headers_complete = http_header_done_cb;
		this->setting.on_message_complete = http_message_done_cb;
		this->setting.on_body = http_body_cb;
		this->setting.on_url = http_url_cb;
		this->setting.on_status = http_status_cb;
		this->setting.on_header_field = http_header_field_cb;
		this->setting.on_header_value = http_header_value_cb;

		//��ʼ�����ջ�����
		int ret = this->alloc_recv_buf(default_recv_buf);
		if (ret){
			return ret;
		}

		//��ʼ��body��
		this->body.buf = ngx_calloc_buf(this->pool);
		this->body.next = NULL;

		//��ʼ��headers_in
		this->headers_in = ngx_list_create(this->pool,8,sizeof(ngx_table_elt_t));
		if (this->headers_in == NULL){
			return -1;
		}

		return 0;
	}

	int http_request::run_http_parser( const char *data,size_t len,bool *done )
	{
		*done =false;
		size_t nparsed = http_parser_execute(&this->parser, &this->setting,data,len);

		//����
		if (nparsed == 0)
			return -1;

		//��ɽ��������س���nparsedΪ�����������ݣ���һ������len
		if (this->state == DONE)
			*done = true;
		else if (nparsed != len){
			//û�н����꣬�����ֲ��ȣ�˵���м����������
			return -1;
		}
		
		return (int)nparsed;
	}

	int http_request::alloc_recv_buf( size_t size /*= ALLOC_PAGESIZE*/ )
	{
		ngx_chain_t * last_chain = &recv_chain;
		while(last_chain->next != NULL)
			last_chain = last_chain->next;

		if (last_chain->buf){
			last_chain->next = ngx_alloc_chain_link(pool);
			last_chain->next->buf = NULL;
			last_chain->next->next = NULL;
			last_chain = last_chain->next;
		}

		//����buf
		buf = ngx_create_temp_buf(pool,size);
		last_chain->buf = buf;
		return 0;
	}

	const ngx_str_t * http_request::get_in_header( const char * field,size_t len )
	{
		//����headers_in,�������Կ��Ǽ���hash���Ż�
		ngx_list_part_t * part = &this->headers_in->part;
		ngx_table_elt_t *data = (ngx_table_elt_t *)part->elts;
		for (int i = 0 ;; i++) {
			if (i >= part->nelts) {
				if (part->next == NULL) {
					break;
				}

				part = part->next;

				data = (ngx_table_elt_t *)part->elts;
				i = 0;
			}

			//���жϳ��ȣ������ַ���Ƶ���Ƚ�
			if (len == data[i].key.len && ngx_strncmp(field,data[i].key.data,len) == 0){
				return &(data[i].value);
			}

		}

		return NULL;
	}


	int http_request::set_out_first_line( const char * line,size_t len )
	{
		int ret = ngx_str_alloc_cpy(&out_first_line,line,len);
		if (ret){
			return -1;
		}

		return 0;
	}

	int http_request::add_out_header( const char * field , size_t field_len,
		const char * value , size_t value_len)
	{
		if (headers_out == NULL){
			headers_out = ngx_list_create(this->pool,8,sizeof(ngx_table_elt_t));
			if (headers_out == NULL){
				return -1;
			}
		}

		ngx_table_elt_t * header = (ngx_table_elt_t*)ngx_list_push(headers_out);
		if (header == NULL){
			return -1;
		}
		ngx_memzero(header,sizeof(ngx_table_elt_t));

		int ret = ngx_str_alloc_cpy(&header->key,(const u_char*)field,field_len);
		if(ret ){
			return -1;
		}

		ret = ngx_str_alloc_cpy(&header->value,value,value_len);
		if(ret ){
			return -1;
		}

		return 0;
	}


	int http_request::add_out_body( const char * body,size_t length,cleanup_pt clean /*= NULL*/ )
	{
		ngx_buf_t *b;
		ngx_chain_t * last_chain = &body_out_chain;
		while(last_chain->next != NULL)
			last_chain = last_chain->next;

		if (last_chain->buf){
			last_chain->next = ngx_alloc_chain_link(pool);
			last_chain->next->buf = NULL;
			last_chain->next->next = NULL;
			last_chain = last_chain->next;
		}

		//copy
		if (clean == NULL){
			b = ngx_create_temp_buf(pool,length);
			last_chain->buf = b;
			ngx_memcpy(b->start,body,length);
			b->last = b->start + length;

		}else{
			b = ngx_calloc_buf(this->pool);
			last_chain->buf = b;

			b->start =  (char*)body;
			b->pos = b->start;
			b->end = b->start + length;
			b->last = b->end;

			ngx_pool_cleanup_t * cl = ngx_pool_cleanup_add(this->pool,0);
			cl->data = (void *)body;
			cl->handler = clean;
		}

		return 0;
	}

	int http_request::package_request()
	{
		//����ͷ������
		int len = 0;
		int crlf_len = sizeof(CRLF) - 1;
		//first line
		len += out_first_line.len + crlf_len;

		//headers
		ngx_list_part_t * part = &this->headers_out->part;
		ngx_table_elt_t *data = (ngx_table_elt_t *)part->elts;
		for (int i = 0 ;; i++) {
			if (i >= part->nelts) {
				if (part->next == NULL) {
					break;
				}

				part = part->next;

				data = (ngx_table_elt_t *)part->elts;
				i = 0;
			}

			len += data[i].key.len + sizeof(": ") - 1
				+ data[i].value.len + crlf_len;
		}

		//header end
		len += crlf_len;

		ngx_buf_t *b = ngx_create_temp_buf(this->pool, len);
		if (b == NULL) {
			return -1;
		}

		//first line copy
		b->last = ngx_copy(b->last,out_first_line.data,out_first_line.len);
		*b->last++ = CR; *b->last++ = LF;

		part = &this->headers_out->part;
		data = (ngx_table_elt_t *)part->elts;
		for (int i = 0 ;; i++) {
			if (i >= part->nelts) {
				if (part->next == NULL) {
					break;
				}

				part = part->next;

				data = (ngx_table_elt_t *)part->elts;
				i = 0;
			}

			b->last = ngx_copy(b->last, data[i].key.data, data[i].key.len);
			*b->last++ = ':'; *b->last++ = ' ';
			b->last = ngx_copy(b->last, data[i].value.data ,data[i].value.len);
			*b->last++ = CR; *b->last++ = LF;

		}

		*b->last++ = CR; *b->last++ = LF;

		send_chain.buf = b;
		if (body_out_chain.buf != NULL){
			send_chain.next = &body_out_chain;
		}else{
			send_chain.next = NULL;
		}
		return 0;
	}

	int http_request::http_header_start_cb( http_parser* p)
	{
		http_request * r = (http_request *)p->data;
		r->state = START;
		return 0;
	}

	int http_request::http_header_done_cb( http_parser* p)
	{
		http_request * r = (http_request *)p->data;
		r->state = HEADER_DONE;

		//����ͷ��������Ϣ

		//���Content-Length
		const ngx_str_t * cl = r->get_in_header("Content-Length");
		if (cl != NULL){
			r->content_length = ngx_atoi(cl->data,cl->len);
			if (r->content_length > 0 && 
				r->content_length >= r->max_body_size){
					return -1;
			}
		}

		return 0;
	}

	int http_request::http_message_done_cb( http_parser* p)
	{
		http_request * r = (http_request *)p->data;
		r->state = DONE;

		//break msg parser
		return 1;
	}

	int http_request::http_url_cb( http_parser*p, const char *at, size_t length )
	{
		http_request * r = (http_request *)p->data;

		return r->set_parse_str( &r->uri,(u_char *)at, length );
	}

	int http_request::http_status_cb( http_parser*p, const char *at, size_t length )
	{
		http_request * r = (http_request *)p->data;
		return r->set_parse_str( &r->status,(u_char *)at, length );
	}

	int http_request::http_header_field_cb( http_parser*p, const char *at, size_t length )
	{
		http_request * r = (http_request *)p->data;

		if (r->state != HEADER_FIELD){
			//������δ����������ߴ�HEADER_VALUE״̬�л�����
			r->header_last = (ngx_table_elt_t*)ngx_list_push(r->headers_in);
			if (r->header_last == NULL){
				return -1;
			}
			ngx_memzero(r->header_last,sizeof(ngx_table_elt_t));
		}

		r->state = HEADER_FIELD;

		return r->set_parse_str( &r->header_last->key,(u_char *)at, length );
	}

	int http_request::http_header_value_cb( http_parser*p, const char *at, size_t length )
	{
		http_request * r = (http_request *)p->data;

		r->state = HEADER_VALUE;
		return r->set_parse_str( &r->header_last->value,(u_char *)at, length );
	}

	int http_request::http_body_cb( http_parser*p, const char *at, size_t length )
	{
		http_request * r = (http_request *)p->data;
		//����body������buf�е�λ��
		ngx_chain_t *last_chain =&r->body;
		while(last_chain->next != NULL)
			last_chain = last_chain->next;

		ngx_buf_t *b = last_chain->buf;
		if (b->start == NULL){
			b->start = b->pos = (u_char *)at;
			b->end = b->last = (u_char *)at +length;
			return 0;
		}

		//�Ա�at�͵�ǰbufָ����ڴ���Ƿ�����
		if ((u_char *)at == b->end){
			//����
			b->end += length;
			b->last = b->end;
		}else{
			//�����µ�buf��
			ngx_chain_t * new_chain = ngx_alloc_chain_link(r->pool);
			new_chain->buf = ngx_calloc_buf(r->pool);
			new_chain->next = NULL;
			last_chain->next = new_chain;

			new_chain->buf->start = (u_char *)at;
			new_chain->buf->end = (u_char *)at + length;
			new_chain->buf->last = new_chain->buf->end;
		}

		return 0;
	}

	void http_request::default_cleanup( void *data )
	{
		ngx_free(data);
	}

}