/*
 * ngx_http_rrd_module.c
 *
 *  Created on: Feb 10, 2011
 *      Author: abonavita
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* The following could be in a header but there is no point in
 * exporting anything. So we keep it and at the beginning to avoid
 * compiler complaints about things being used without being
 * declared.
 */
static char *ngx_http_rrd_post_command(ngx_conf_t *cf, void *data, void *conf);
static ngx_int_t ngx_http_rrd_handler(ngx_http_request_t *r);
static void *ngx_http_rrd_create_loc_conf(ngx_conf_t *conf);

/* Module declaration */
static ngx_http_module_t  ngx_http_rrd_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_rrd_create_loc_conf,                          /* create location configuration */
    NULL                           /* merge location configuration */
};



/* Structure storing configuration specific to this module. */
typedef struct {
	ngx_str_t db_name;
} ngx_http_rrd_module_conf_t;
/* The module configuration creation function. */
static void *ngx_http_rrd_create_loc_conf(ngx_conf_t *conf)
{
    ngx_http_rrd_module_conf_t  *rrd_conf;

    rrd_conf = ngx_pcalloc(conf->pool, sizeof(ngx_http_rrd_module_conf_t));
    if (rrd_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    /*ngx_str_null(&(rrd_conf->db_name));*/
    return rrd_conf;
}

/* Commands offered by this module. */
static ngx_conf_post_t ngx_http_rrd_post = {
		ngx_http_rrd_post_command
};
static ngx_command_t  ngx_http_rrd_commands[] = {

    { ngx_string("rrd"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rrd_module_conf_t, db_name),
      &ngx_http_rrd_post},

      ngx_null_command
};

ngx_module_t  ngx_http_rrd_module = {
    NGX_MODULE_V1,
    &ngx_http_rrd_module_ctx,      /* module context */
    ngx_http_rrd_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/*  Called as post processing the command rrd. The argument
 * is handled by ngx_conf_st_str_slot. */
static char*
ngx_http_rrd_post_command(ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_core_loc_conf_t  *core_loc_conf;

    core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    core_loc_conf->handler = ngx_http_rrd_handler;

    return NGX_CONF_OK;
}

/* The messages (OK, errors) that can be sent by this module. Note that
 * the important thing returned is the status (this is a REST-like API).
 */
static ngx_str_t OK_MSG =
		ngx_string("You make the rock-n-roll go round, Robin.");
/*static ngx_str_t ERROR_MSG = ngx_string("You lose.");*/

ngx_buf_t * ngx_http_rrd_create_buf_from_str(ngx_pool_t *pool, ngx_str_t s)
{
	ngx_buf_t *buf;
	buf = ngx_calloc_buf(pool);
	if (NULL == buf) {
		return  NULL;
	}
	buf->start = s.data;
	buf->end = s.data + s.len;
	buf->pos = buf->start;
	buf->last = buf->end;
	buf->memory = 1;
	return buf;
}
/* The actual handler that will process requests. */
static ngx_int_t
ngx_http_rrd_handler(ngx_http_request_t *r)
{
	ngx_int_t ok_tmp;
	ngx_buf_t *buf;

	r->headers_out.status = NGX_HTTP_OK;
	ok_tmp = ngx_http_send_header(r);
	if (ok_tmp != NGX_OK) {
		return ok_tmp;
	}
	/* Create buffer for message */
	buf = ngx_http_rrd_create_buf_from_str(r->pool, OK_MSG);
	if (NULL==buf) {return NGX_HTTP_INTERNAL_SERVER_ERROR;}

	ngx_chain_t out_chain;
	out_chain.buf = buf;

	ngx_http_rrd_module_conf_t *rrd_conf;
	rrd_conf = ngx_http_get_module_loc_conf(r, ngx_http_rrd_module);
	buf = ngx_http_rrd_create_buf_from_str(r->pool, rrd_conf->db_name);
	if (NULL==buf) {return NGX_HTTP_INTERNAL_SERVER_ERROR;}
	buf->last_in_chain = 1;
	buf->last_buf = 1;
	ngx_chain_t next;
	out_chain.next = &next;
	next.buf = buf;
	next.next = NULL;

	return ngx_http_output_filter(r, &out_chain);
}


