/*
 * ngx_http_rrd_module.c
 *
 *  Created on: Feb 10, 2011
 *      Author: abonavita
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <rrd.h>

/* The following could be in a header but there is no point in
 * exporting anything. So we keep it and at the beginning to avoid
 * compiler complaints about things being used without being
 * declared.
 */
static char *ngx_http_rrd_post_command(ngx_conf_t *cf, void *data, void *conf);
static void *ngx_http_rrd_create_loc_conf(ngx_conf_t *conf);
static char *ngx_http_rrd_merge_loc_conf(ngx_conf_t *cf,
                                          void *parent, void *child);
static ngx_int_t ngx_http_rrd_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_rrd_update_database(ngx_http_request_t *r);
static ngx_int_t ngx_http_rrd_show_graph(ngx_http_request_t *r);
static void ngx_http_rrd_body_received(ngx_http_request_t *r);

/* Module declaration */
static ngx_http_module_t  ngx_http_rrd_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_rrd_create_loc_conf,  /* create location configuration */
    ngx_http_rrd_merge_loc_conf    /* merge location configuration */
};

/* Structure storing configuration specific to this module. */
typedef struct {
    ngx_str_t db_name; /* Name of rrd database. */
    ngx_path_t* rrd_image_temp_path;
} ngx_http_rrd_loc_conf_t;

/* Default values. */
static ngx_path_init_t  ngx_http_rrd_temp_path = {
    ngx_string("rrd_temp"), { 0, 0, 0 }
};

/* The module configuration creation function. */
static void *ngx_http_rrd_create_loc_conf(ngx_conf_t *conf)
{
    ngx_http_rrd_loc_conf_t  *rrd_conf;

    rrd_conf = ngx_pcalloc(conf->pool, sizeof(ngx_http_rrd_loc_conf_t));
    if (rrd_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    /*ngx_str_null(&(rrd_conf->db_name));*/
    return rrd_conf;
}
/*  Merges location configurations. */
static char *
ngx_http_rrd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_rrd_loc_conf_t* plcf = parent;
    ngx_http_rrd_loc_conf_t* clcf = child;

    if (ngx_conf_merge_path_value(cf, &clcf->rrd_image_temp_path,
                              plcf->rrd_image_temp_path,
                              &ngx_http_rrd_temp_path)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
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
      offsetof(ngx_http_rrd_loc_conf_t, db_name),
      &ngx_http_rrd_post},

    { ngx_string("rrd_image_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rrd_loc_conf_t, rrd_image_temp_path),
      NULL },

      ngx_null_command
};

/*
 *  Called once per process to initialize the rrd lib.
 */
static ngx_int_t ngx_http_rrd_init_process(ngx_cycle_t *cycle) {
    rrd_get_context();
    ngx_log_error_core(NGX_DEBUG, cycle->log, 0, "rrd: init");
    return NGX_OK;
}

ngx_module_t  ngx_http_rrd_module = {
    NGX_MODULE_V1,
    &ngx_http_rrd_module_ctx,      /* module context */
    ngx_http_rrd_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_rrd_init_process,     /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/*  Called as post processing the command "rrd". The argument
 * of this command is handled by ngx_conf_set_str_slot, then this
 * function is called. */
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
static ngx_str_t ERR_UPDATE_MSG =
        ngx_string("Problem updating database with submitted value: ");
static ngx_str_t ERR_GRAPH_MSG =
        ngx_string("Problem graphing database.");
#define ERR_BAD_METHOD_MSG_CSTR "rrd module supports only GET and POST verbs."
static ngx_str_t ERR_BAD_METHOD_MSG =
        ngx_string(ERR_BAD_METHOD_MSG_CSTR);
static ngx_str_t ERR_BAD_CONTENT_TYPE_MSG =
        ngx_string("rrd module supports only application/x-www-form-urlencoded"
                " content type for now.");
static ngx_str_t IMAGE_PNG = ngx_string("image/png");
static ngx_str_t TEXT_PLAIN = ngx_string("text/plain");
static ngx_str_t WWW_FORM_URLENCODED =
        ngx_string("application/x-www-form-urlencoded");

/*
 * Helper function to create a chain from an array of ngx_str.
 */
ngx_chain_t *ngx_http_rrd_create_chain(ngx_pool_t *pool,
                                  ngx_uint_t sarray_len, ngx_str_t **sarray)
{
    /* Allocate sarray_len chain links */
    ngx_chain_t *out_chain = ngx_pcalloc(pool, sarray_len * sizeof(ngx_chain_t));
    if (NULL == out_chain) {
        return NULL;
    }
    /* Allocate sarray_len buffers */
    ngx_buf_t *buf = ngx_pcalloc(pool, sarray_len * sizeof(ngx_buf_t));
    if (NULL == buf) {
        /* Don't try to free memory, nginx will do it when throwing away the
         * pool.
         */
        return NULL;
    }

    ngx_uint_t i;
    for (i = 0; i<sarray_len - 1; i++){
        out_chain[i].buf = &(buf[i]);
        out_chain[i].next = &out_chain[i+1];
        buf[i].start = buf[i].pos = sarray[i]->data;
        buf[i].end = buf[i].last = sarray[i]->data + sarray[i]->len;
        buf[i].memory = 1;
    }
    /* Last one is slightly different. */
    out_chain[i].buf = &(buf[i]);
    out_chain[i].next = NULL; /* diff */
    buf[i].start = buf[i].pos = sarray[i]->data;
    buf[i].end = buf[i].last = sarray[i]->data + sarray[i]->len;
    buf[i].memory = 1;
    buf[i].last_in_chain = 1;
    buf[i].last_buf = 1;
    return out_chain;
}
/*
 * Helper function to send an array of ngx_str as response to a request.
 */
static ngx_int_t ngx_http_rrd_output_200(ngx_http_request_t *r,
                                  ngx_uint_t sarray_len, ngx_str_t **sarray)
{
	ngx_log_t *log = r->connection->log;
    ngx_chain_t *out_chain = ngx_http_rrd_create_chain(r->pool,
                                                       sarray_len, sarray);
    if (NULL == out_chain) {
        /* nothing else I can do... */
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "memory alloc pb @ngx_http_rrd_body_received");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_int_t rc;
    r->headers_out.status = NGX_HTTP_OK;
    /* Figure out size of content. */
    ngx_uint_t i, content_length = 0;
    for (i = 0; i<sarray_len; i++){
        content_length += sarray[i]->len;
    }
    r->headers_out.content_length_n = content_length;
    rc = ngx_http_send_header(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "pb sending header @ngx_http_rrd_body_received");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_output_filter(r, out_chain);
}
/*
 * Helper function to send a temporary file (image) as 200 response.
 */
static ngx_int_t ngx_http_rrd_png_file_200(ngx_http_request_t *r,
                                  ngx_file_t* src_file)
{
    ngx_log_t *log = r->connection->log;

    /* Create chain of one buffer with the file */
    ngx_chain_t *out_chain = ngx_alloc_chain_link(r->pool);
    if (NULL == out_chain) {
        /* nothing else I can do... */
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "chain alloc pb @ngx_http_rrd_png_file_200");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_buf_t *buf = ngx_alloc_buf(r->pool);
    if (NULL == buf) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "buffer alloc pb @ngx_http_rrd_png_file_200");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    off_t seek_size = lseek(src_file->fd, 0, SEEK_END);
    if (seek_size < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "Unable to read file size. fd:%d, r:%O");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    buf->file = src_file;
    buf->in_file = 1;
    buf->last_buf = 1;
    buf->last_in_chain = 1;
    buf->file_pos = 0;
    buf->file_last = seek_size;
    out_chain->buf = buf;
    out_chain->next = NULL;

    /* Header. */
    ngx_int_t rc;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = seek_size;
    r->headers_out.content_type.data = IMAGE_PNG.data;
    r->headers_out.content_type.len = IMAGE_PNG.len;
    rc = ngx_http_send_header(r);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              "pb sending header @ngx_http_rrd_png_file_200");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_output_filter(r, out_chain);
}
/* The actual handler that will process requests. */
ngx_int_t ngx_http_rrd_handler(ngx_http_request_t *r)
{
    ngx_log_t                 *log;
    log = r->connection->log;


    if (NGX_HTTP_GET == r->method) {
        return ngx_http_rrd_show_graph(r);
    } else if (NGX_HTTP_POST == r->method) {
        return ngx_http_rrd_update_database(r);
    } else if (NGX_HTTP_HEAD == r->method) {
        /*  HEAD is supposed to give you the headers the GET would give you.
         * So, we're providing the content-type.
         */
        r->headers_out.status = NGX_HTTP_OK;
        r->header_only = 1;
        r->headers_out.content_type.data = IMAGE_PNG.data;
        r->headers_out.content_type.len = IMAGE_PNG.len;
        return ngx_http_send_header(r);
    } else {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              ERR_BAD_METHOD_MSG_CSTR);
        ngx_http_complex_value_t cv = {ERR_BAD_METHOD_MSG, NULL, NULL, NULL};

        return ngx_http_send_response(r, NGX_HTTP_NOT_ALLOWED,
                                      &TEXT_PLAIN, &cv);
    }
}
/*
 *  The handler for POST requests (that update the RRD database). The
 * thing here is to remember that when this is called, the body might
 * not be available. So, you must to register an extra callback that
 * will be called when the body is available.
 */
ngx_int_t ngx_http_rrd_update_database(ngx_http_request_t *r)
{
    ngx_log_t *log = r->connection->log;
    ngx_int_t rc;

    if (r->headers_in.content_type == NULL
            || r->headers_in.content_type->value.data == NULL
            || r->headers_in.content_type->value.len != WWW_FORM_URLENCODED.len
            || ngx_strncasecmp(r->headers_in.content_type->value.data,
                    (u_char *) WWW_FORM_URLENCODED.data,
                    WWW_FORM_URLENCODED.len) != 0)
    {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                              (char *) ERR_BAD_CONTENT_TYPE_MSG.data);
        ngx_http_complex_value_t cv = {ERR_BAD_CONTENT_TYPE_MSG, NULL, NULL, NULL};

        return ngx_http_send_response(r, NGX_HTTP_NOT_ALLOWED,
                                      &TEXT_PLAIN, &cv);
    }
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                          "rrd module: Content-type is OK. Proceeding.");

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                   "rrd module: start reading client request body");

    rc = ngx_http_read_client_request_body(r, ngx_http_rrd_body_received);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        /*  nginx will call the body_received when needed. Returning
         * NGX_DONE will prevent nginx from calling ngx_http_finalize_request
         * (which we will call in body_received) */
        return NGX_DONE;
    }
    if (NGX_OK == rc) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                      "rrd module: client request body already read");
        return rc;
    }

    ngx_log_error(NGX_LOG_ALERT, log, 0,
                   "rrd module: unexpected response code from"
                   "ngx_http_read_client_request_body : %u", rc);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
/*
 *  Called when the full body has been received. Even if the body is sent in
 *  multiple chunks, this will be called only once when everything has
 *  been received.
 */
void ngx_http_rrd_body_received(ngx_http_request_t *r)
{
    ngx_log_t *log = r->connection->log;
    ngx_chain_t *body_chain = r->request_body->bufs;
    /* Use the content length as a max for our value. */
    u_char* copy_idx;
    /*  In theory I should check for the size of the body to avoid loading
     * too much stuff in memory. However this is already handled by nginx
     * client_max_body_size.
     */
    u_char* rrd_value = copy_idx =
            ngx_palloc(r->pool, r->headers_in.content_length_n);
    if (NULL == rrd_value) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                       "Alloc problem @ngx_http_rrd_body_received/1");
        return ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    u_char* p;
    /* TODO: rewrite this to first READ in mem, then look for = and urldecode*/
    ngx_int_t looking_for_eq = 1;
    do {
        ngx_buf_t *temp_buf;
        if (body_chain->buf->in_file) {
            ngx_buf_t * file_buf = body_chain->buf;
            /* Read it first in mem. This is unfortunately blocking.
             * TODO : non-blocking. HttpUploadModule ?
             */
            temp_buf = ngx_create_temp_buf(r->pool, ngx_buf_size(file_buf));
            if (NULL == temp_buf) {
                ngx_log_error(NGX_LOG_ALERT, log, 0,
                               "Alloc problem @ngx_http_rrd_body_received/2");
                return ngx_http_finalize_request(r,
                                         NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
            ssize_t read_n;
            read_n = ngx_read_file(file_buf->file, temp_buf->start,
                                   ngx_buf_size(file_buf), 0);
            if (read_n < 0) {
                /* Problem already logged by read_file. */
                return ngx_http_finalize_request(r,
                                         NGX_HTTP_INTERNAL_SERVER_ERROR);
            } else {
                temp_buf->last = temp_buf->start + read_n;
            }
        } else {
            temp_buf = body_chain->buf;
        }
        p = temp_buf->start;
        while (p!=temp_buf->last && looking_for_eq) {
            if ('=' == *(p++)) {
                looking_for_eq = 0;
            }
        }
        if (!looking_for_eq) {
            u_char *dst = copy_idx;
            u_char *src = p;
            /*
             *   This won't work if buffer boundary is in the middle of a
             *  percent-encoded string (which is unlikely to happen I would
             *  say. Should try to unit test this situation.
             */
            ngx_unescape_uri(&dst, &src, temp_buf->last - p, 0);
            copy_idx = dst;
        }
        body_chain = body_chain->next;
    } while (NULL != body_chain);
    *copy_idx = '\x0';

    ngx_http_rrd_loc_conf_t *rrd_conf;
    rrd_conf = ngx_http_get_module_loc_conf(r, ngx_http_rrd_module);

    int rrd_rc;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                  "rrd_update_r (%V, NULL, 1, %s)", &rrd_conf->db_name,
                  rrd_value);
    rrd_clear_error();
    rrd_rc = rrd_update_r((const char*) rrd_conf->db_name.data, NULL,
                          1, (const char **)&rrd_value);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                  "rrd_update_r returned: %d", rrd_rc);
    ngx_int_t rc;
    if (rrd_rc < 0) {
        ngx_str_t val;
        val.data = rrd_value;
        val.len = copy_idx - rrd_value;
        ngx_str_t* out_str[] = {&ERR_UPDATE_MSG, &(rrd_conf->db_name), &val};
        rc = ngx_http_rrd_output_200(r, 3, out_str);
    } else {
        ngx_str_t* out_str[] = {&OK_MSG, &(rrd_conf->db_name)};
        rc = ngx_http_rrd_output_200(r, 2, out_str);
    }
    ngx_http_finalize_request(r, rc);
}

/*
 *  Returns an array of char* that can be passed to rrd_graph. Returns
 * NULL in case of failure. argc parameter is modified to indicate the
 * number of arguments actually present in the returned array (because
 * this depends on the data structure).
 */
static char** ngx_http_rrd_create_graph_arg(int* argc, ngx_pool_t* pool,
                                            ngx_str_t* temp_file_name,
                                            ngx_str_t* db_name) {
    *argc = 4;
    char** argv;
    argv = ngx_palloc(pool, (*argc) * sizeof(char *));
    if (NULL == argv) {
        *argc = -1;
        return NULL;
    }
    /*  Copy it because ngx_str_t does not guarantee the presence of \x0 and
     * char* requires it.
     */
    char* c_temp_file_name =
            ngx_palloc(pool, (temp_file_name->len + 1) * sizeof(char *));
    if (NULL == c_temp_file_name) {
        *argc = -1;
        return NULL;
    }
    ngx_memcpy(c_temp_file_name, temp_file_name->data, temp_file_name->len);
    c_temp_file_name[temp_file_name->len] = '\x0';

    int c_str_size = 4+5+1+50+1+20+8+1;
    u_char* c_def_val01 =
            ngx_palloc(pool, (c_str_size) * sizeof(char *));
    u_char* last = ngx_slprintf(c_def_val01, c_def_val01+c_str_size-1, "DEF:%s=%V:%s:AVERAGE\x0", "val01", db_name, "resptime");
    *last = '\x0';

    c_str_size = 6+5+7+1;
    u_char* c_draw_val01 =
            ngx_palloc(pool, (c_str_size) * sizeof(char *));
    last = ngx_slprintf(c_draw_val01, c_draw_val01+c_str_size-1, "LINE2:%s#FF0000\x0", "val01");
    *last = '\x0';
    argv[0] = "graph";
    argv[1] = c_temp_file_name;
    argv[2] = (char*) c_def_val01;
    argv[3] = (char*) c_draw_val01;
    return argv;

}
static void ngx_http_rrd_free_graph_arg(ngx_pool_t* pool, int argc, char** argv) {
    int i;
    for (i=1;i<argc;i++) {
        ngx_pfree(pool, argv[i]);
    }
    ngx_pfree(pool, argv);
}
/*
 *  Handles the GET requests by getting RRD to graph and sending the result
 * as an HTTP response.
 */
static ngx_int_t ngx_http_rrd_show_graph(ngx_http_request_t *r)
{
    ngx_log_t* log = r->connection->log;
    ngx_http_rrd_loc_conf_t *rrd_conf;
    rrd_conf = ngx_http_get_module_loc_conf(r, ngx_http_rrd_module);

    /* Prepare file for rrdgraph */
    ngx_file_t temp_file;
    ngx_int_t rc;
    temp_file.fd = NGX_INVALID_FILE;
    temp_file.log = r->connection->log;
    /* Persistent needed to retrieve size and clean afterwards. */
    rc = ngx_create_temp_file(&temp_file, rrd_conf->rrd_image_temp_path, r->pool,
                              1, 1, 0);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Prepare args for rrdgraph */
    int rrd_argc;
    char** rrd_arg = ngx_http_rrd_create_graph_arg(&rrd_argc, r->pool,
                               &temp_file.name, &rrd_conf->db_name);
    char    **calcpr;
    int       xsize, ysize;
    double    ymin, ymax;
    rrd_clear_error();
    int rrd_rc = rrd_graph(rrd_argc, rrd_arg,
                           &calcpr, &xsize, &ysize, NULL, &ymin, &ymax);
    ngx_http_rrd_free_graph_arg(r->pool, rrd_argc, rrd_arg);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                  "rrd_graph (%s, %s, %s, %s) returned %d.",
                  rrd_arg[0], rrd_arg[1], rrd_arg[2], rrd_arg[3],
                  rrd_rc);
    if (rrd_rc < 0) {
        ngx_str_t* out_str[] = {&ERR_GRAPH_MSG};
        return ngx_http_rrd_output_200(r, sizeof(out_str)/sizeof(ngx_str_t*), out_str);
    } else {
        return ngx_http_rrd_png_file_200(r, &temp_file);
    }
}

