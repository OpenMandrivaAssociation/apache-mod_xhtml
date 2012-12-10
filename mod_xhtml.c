/*

	Copyright (c) 2003-4, WebThing Ltd
	Author: Nick Kew <nick@webthing.com>

	Includes code re-used from mod_include.c
	Copyright (c) 1999-2004 The Apache Software Foundation


This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/


/* XHTML namespace */
#define XHTML10	"http://www.w3.org/1999/xhtml"
#define SSI	"http://apache.webthing.com/ssi#"

/* There is no existing namespace for SSI, so we have to invent one
	http://apache.webthing.com/ssi#
   It works perfectly simply as a namespace: SSI directives take the form
   <!--#if expr="foo bar"--> becomes <ssi:if expr="foo bar"/>
   <!--#set var="foo" value="bar"--> becomes <ssi:set var="foo" value="bar"/>
   etc.

  This module implements SSI both as a namespace and in-comment.

  Incompleteness:
	<!--#exec .. --> (deprecated in Apache) is not implemented in mod_xhtml
	Regular expressions in expr parsing are not supported.
*/

/*
  (1) Namespace Handler for XHTML	(http://www.w3.org/1999/xhtml)
  (2) Implementation of XHTML with serverside includes (SSI)
  (3) Namespace handler for SSI

  (1) will process XHTML markup to Appendix-C compatible XHTML
  that can be sent to current and older web browsers as text/html

   * All HTML is written in the default namespace
   * Empty elements end with " />"
   * Substitutes any META element that sets content-type

  (2) implements all of (1), and additionally implements SSI parsing

  (3) implements SSI as a namespace <ssi:if expr="foo"/>, etc.

  Both (1) and (2) implement the XHTML namespace, and are therefore
  mutually exclusive.  (3) implements SSI namespace, and can be used
  with either (1) or (2).  If you use any classic <!--# ... --> SSI
  directives, you'll need (2); otherwise use (1).

  To implement SSI as a namespace without reference to Appendix C,
  (3) can be used on its own.  This works with other XML.

BUGS:
   * If there is a default namespace defined for something other
     than XHTML, it'll get confused.
   * Doesn't reliably support charset declaration in a META element
   * Incomplete SSI support (see above)

See the website for details: http://apache.webthing.com/mod_xhtml/

*/
/* For code cut&paste from mod_include */
#define DEBUG_DUMP_UNMATCHED(x,y)
#define DEBUG_DUMP_TOKEN(x,y)
#define DEBUG_DUMP_TREE(x,y)
#define DEBUG_DUMP_EVAL(x,y)

#include <ctype.h>

#include "xmlns.h"
#include <http_log.h>
#include <http_config.h>
#include <http_request.h>
#include <ap_provider.h>
#include <apr_strings.h>
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <string.h>

#include <util_script.h>

#define F ctx->f
#define BB ctx->bb

module AP_MODULE_DECLARE_DATA xhtml_module ;

const xml_char_t* (*xmlns_get_attr_name)(const xmlns_attr_t* attrs, int attnum);
const xml_char_t* (*xmlns_get_attr_val)(const xmlns_attr_t* attrs, int attnum);
int (*xmlns_get_attr_parsed)(const xmlns_attr_t* attrs, int attnum, parsedname* res);
void (*xmlns_suppress_output)(xmlns_public*, int onoff);

static void xmlns_funcs(void) {
  xmlns_get_attr_name = APR_RETRIEVE_OPTIONAL_FN(mod_xmlns_get_attr_name);
  xmlns_get_attr_val = APR_RETRIEVE_OPTIONAL_FN(mod_xmlns_get_attr_val);
  xmlns_get_attr_parsed = APR_RETRIEVE_OPTIONAL_FN(mod_xmlns_get_attr_parsed);
  xmlns_suppress_output = APR_RETRIEVE_OPTIONAL_FN(mod_xmlns_suppress_output);
}

static char* ap_ssi_parse_string(request_rec *r, const char *in) ;

typedef  enum { SIZEFMT_ABBREV, SIZEFMT_BYTES } sizefmt_t ;
typedef struct {
  const char* timefmt ;
  const char* errmsg ;
  sizefmt_t sizefmt ;
} xhtml_conf ;

typedef enum { IF_UNSATISFIED, IF_MATCH, IF_SATISFIED } ssi_cond_val ;
typedef struct ssi_condition {
  ssi_cond_val condition ;
  struct ssi_condition* parent ;
} ssi_condition ;

typedef struct {
  ssi_condition* cond ;
  apr_table_t* args ;
  const char* errmsg ;
  const char* timefmt ;
  sizefmt_t sizefmt ;
  size_t refcount ;
} ssi_ctx ;

static int is_empty(const parsedname* name) {
  const char** p ;
  static const char* empty_elts[] = {
    "br" ,
    "link" ,
    "img" ,
    "hr" ,
    "input" ,
    "meta" ,
    "base" ,
    "area" ,
    "param" ,
    "col" ,
    "frame" ,
    "isindex" ,
    "basefont" ,
    NULL
  } ;
  for ( p = empty_elts ; *p ; ++p )
    if ( ( name->eltlen == strlen(*p) )
	&& !strncmp( *p, name->elt, name->eltlen) )
      return 1 ;
  return 0 ;
}
static int xhtml_start(xmlns_public* ctx, const parsedname* name3,
	const xmlns_attr_t* atts) {
  int have_default_ns = 0 ;
  int i ;
  const xml_char_t* a0 ;
  const xml_char_t* a1 ;
//  ssi_ctx* sctx = xmlns_get_appdata(ctx, &xhtml_module) ;
  ssi_ctx* sctx = ap_get_module_config(ctx->f->r->request_config, &xhtml_module);
  ssi_condition* cond ;
  parsedname a3 ;
  if ( sctx )
    for ( cond = sctx->cond ; cond ; cond = cond->parent )
      if ( cond->condition != IF_MATCH )
	return OK ;

  if ( ! strncmp(name3->elt, "meta", 4) ) {
    for ( i = 0 ; ; ++i ) {
      a0 = xmlns_get_attr_name(atts, i) ;
      if ( ! a0 )
	break ;
      a1 = xmlns_get_attr_val(atts, i) ;
      if ( !strcasecmp(a0, "http-equiv")
	&& a1
	&& !strcasecmp(a1, "content-type")
      ) {
	ap_fputs(F->next, BB, "<meta http-equiv=\"Content-Type\" "
		"content=\"text/html; charset=utf-8\" />") ;
	return OK ;
      }
    }
  }
  ap_fputc(F->next, BB, '<') ;
  ap_fwrite(F->next, BB, name3->elt, name3->eltlen) ;

  if ( atts ) {
    for ( i = 0 ; ; ++i ) {
      if ( ! xmlns_get_attr_parsed(atts, i, &a3) )
	break ;
      a1 = xmlns_get_attr_val(atts, i) ;
      ap_fputc(F->next, BB, ' ') ;
      switch ( a3.nparts ) {
	case 2:
	  ap_fwrite(F->next, BB, a3.ns, a3.nslen) ;
	  ap_fputc(F->next, BB, ':') ;
	  break ;
	case 3:
	  ap_fwrite(F->next, BB, a3.prefix, a3.prefixlen) ;
	  ap_fputc(F->next, BB, ':') ;
	  break ;
      }
      ap_fwrite(F->next, BB, a3.elt, a3.eltlen) ;
      ap_fputstrs(F->next, BB, "=\"", a1, "\"", NULL) ;
    }
  }

  if ( ! have_default_ns && !strncmp( "html", name3->elt, 4) )
    ap_fputs(F->next, BB, " xmlns=\"http://www.w3.org/1999/xhtml\">") ;
  else if ( is_empty(name3) )
    ap_fputs(F->next, BB, " />") ;
  else
    ap_fputc(F->next, BB, '>') ;
  return OK ;
}
static int xhtml_end(xmlns_public* ctx, const parsedname* name) {
  ssi_ctx* sctx = ap_get_module_config(ctx->f->r->request_config, &xhtml_module);
  ssi_condition* cond ;
  if ( sctx )
    for ( cond = sctx->cond ; cond ; cond = cond->parent )
      if ( cond->condition != IF_MATCH )
	return OK ;
  if ( ! is_empty(name) ) {
    ap_fputs(F->next, BB, "</") ;
    ap_fwrite(F->next, BB, name->elt, name->eltlen) ;
    ap_fputc(F->next, BB, '>') ;
  }
  return OK ;
}



/*
 * +-------------------------------------------------------+
 * |                                                       |
 * |              Conditional Expression Parser
 * |                                                       |
 * +-------------------------------------------------------+
 */
/* conditional expression parser stuff */
typedef enum {
    TOKEN_STRING,
    TOKEN_RE,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_NOT,
    TOKEN_EQ,
    TOKEN_NE,
    TOKEN_RBRACE,
    TOKEN_LBRACE,
    TOKEN_GROUP,
    TOKEN_GE,
    TOKEN_LE,
    TOKEN_GT,
    TOKEN_LT
} token_type_t;
typedef struct {
    token_type_t  type;
    const char   *value;
} token_t;
typedef struct parse_node {
    struct parse_node *parent;
    struct parse_node *left;
    struct parse_node *right;
    token_t token;
    int value;
    int done;
} parse_node_t;

#define TYPE_TOKEN(token, ttype) (token)->type = ttype

static int get_ptoken(apr_pool_t *pool, const char **parse, token_t *token)
{
    const char *p;
    apr_size_t shift;
    int unmatched;

    token->value = NULL;

    if (!*parse) {
        return 0;
    }

    /* Skip leading white space */
    while (isspace(**parse)) {
        ++*parse;
    }

    if (!**parse) {
        *parse = NULL;
        return 0;
    }

    TYPE_TOKEN(token, TOKEN_STRING); /* the default type */
    p = *parse;
    unmatched = 0;

    switch (*(*parse)++) {
    case '(':
        TYPE_TOKEN(token, TOKEN_LBRACE);
        return 0;
    case ')':
        TYPE_TOKEN(token, TOKEN_RBRACE);
        return 0;
    case '=':
        if (**parse == '=') ++*parse;
        TYPE_TOKEN(token, TOKEN_EQ);
        return 0;
    case '!':
        if (**parse == '=') {
            TYPE_TOKEN(token, TOKEN_NE);
            ++*parse;
            return 0;
        }
        TYPE_TOKEN(token, TOKEN_NOT);
        return 0;
    case '\'':
        unmatched = '\'';
        break;
    case '/':
        TYPE_TOKEN(token, TOKEN_RE);
        unmatched = '/';
        break;
    case '|':
        if (**parse == '|') {
            TYPE_TOKEN(token, TOKEN_OR);
            ++*parse;
            return 0;
        }
        break;
    case '&':
        if (**parse == '&') {
            TYPE_TOKEN(token, TOKEN_AND);
            ++*parse;
            return 0;
        }
        break;
    case '>':
        if (**parse == '=') {
            TYPE_TOKEN(token, TOKEN_GE);
            ++*parse;
            return 0;
        }
        TYPE_TOKEN(token, TOKEN_GT);
        return 0;
    case '<':
        if (**parse == '=') {
            TYPE_TOKEN(token, TOKEN_LE);
            ++*parse;
            return 0;
        }
        TYPE_TOKEN(token, TOKEN_LT);
        return 0;
    }

    /* It's a string or regex token
     * Now search for the next token, which finishes this string
     */
    shift = 0;
    p = *parse = token->value = unmatched ? *parse : p;

    for (; **parse; p = ++*parse) {
        if (**parse == '\\') {
            if (!*(++*parse)) {
                p = *parse;
                break;
            }

            ++shift;
        }
        else {
            if (unmatched) {
                if (**parse == unmatched) {
                    unmatched = 0;
                    ++*parse;
                    break;
                }
            } else if (isspace(**parse)) {
                break;
            }
            else {
                int found = 0;

                switch (**parse) {
                case '(':
                case ')':
                case '=':
                case '!':
                case '<':
                case '>':
                    ++found;
                    break;

                case '|':
                case '&':
                    if ((*parse)[1] == **parse) {
                        ++found;
                    }
                    break;
                }

                if (found) {
                    break;
                }
            }
        }
    }

    if (unmatched) {
        token->value = apr_pstrdup(pool, "");
    }
    else {
        apr_size_t len = p - token->value - shift;
        char *c = apr_palloc(pool, len + 1);

        p = token->value;
        token->value = c;

        while (shift--) {
            const char *e = ap_strchr_c(p, '\\');

            memcpy(c, p, e-p);
            c   += e-p;
            *c++ = *++e;
            len -= e-p;
            p    = e+1;
        }

        if (len) {
            memcpy(c, p, len);
        }
        c[len] = '\0';
    }

    return unmatched;
}

static ssi_cond_val test_condition(xmlns_public* ctx, ssi_ctx* sctx) {
    parse_node_t *newnode ;
    parse_node_t *root = NULL ;
    parse_node_t *current = NULL;
    request_rec *r = ctx->f->r ;
    const char* expr = apr_table_get(sctx->args, "expr") ;
    const char *error = "Invalid expression \"%s\" in file %s";
    const char *parse = expr;
    int was_unmatched = 0;
    unsigned regex = 0;

    int was_error = 0;

    if (!parse) {
        return 0;
    }

    /* Create Parse Tree */
    while (1) {
        /* uncomment this to see how the tree a built:
         *
         * DEBUG_DUMP_TREE(ctx, root);
         */
	newnode = apr_pcalloc(ctx->f->r->pool, sizeof(parse_node_t)) ;

        was_unmatched = get_ptoken(r->pool, &parse, &newnode->token);
        if (!parse) {
            break;
        }

        DEBUG_DUMP_UNMATCHED(ctx, was_unmatched);
        DEBUG_DUMP_TOKEN(ctx, &newnode->token);

        if (!current) {
            switch (newnode->token.type) {
            case TOKEN_STRING:
            case TOKEN_NOT:
            case TOKEN_LBRACE:
                root = current = newnode;
                continue;

            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, error, expr,
                              r->filename);
                was_error = 1;
                return sctx->cond->condition ;
            }
        }

        switch (newnode->token.type) {
        case TOKEN_STRING:
            switch (current->token.type) {
            case TOKEN_STRING:
                current->token.value =
                    apr_pstrcat(r->pool, current->token.value,
                                *current->token.value ? " " : "",
                                newnode->token.value, NULL);
                continue;

            case TOKEN_RE:
            case TOKEN_RBRACE:
            case TOKEN_GROUP:
                break;

            default:
                newnode->parent = current;
                current = current->right = newnode;
                continue;
            }
            break;

        case TOKEN_RE:
            switch (current->token.type) {
            case TOKEN_EQ:
            case TOKEN_NE:
                newnode->parent = current;
                current = current->right = newnode;
                ++regex;
                continue;

            default:
                break;
            }
            break;

        case TOKEN_AND:
        case TOKEN_OR:
            switch (current->token.type) {
            case TOKEN_STRING:
            case TOKEN_RE:
            case TOKEN_GROUP:
                current = current->parent;

                while (current) {
                    switch (current->token.type) {
                    case TOKEN_AND:
                    case TOKEN_OR:
                    case TOKEN_LBRACE:
                        break;

                    default:
                        current = current->parent;
                        continue;
                    }
                    break;
                }

                if (!current) {
                    newnode->left = root;
                    root->parent = newnode;
                    current = root = newnode;
                    continue;
                }

                newnode->left = current->right;
                newnode->left->parent = newnode;
                newnode->parent = current;
                current = current->right = newnode;
                continue;

            default:
                break;
            }
            break;

        case TOKEN_EQ:
        case TOKEN_NE:
        case TOKEN_GE:
        case TOKEN_GT:
        case TOKEN_LE:
        case TOKEN_LT:
            if (current->token.type == TOKEN_STRING) {
                current = current->parent;

                if (!current) {
                    newnode->left = root;
                    root->parent = newnode;
                    current = root = newnode;
                    continue;
                }

                switch (current->token.type) {
                case TOKEN_LBRACE:
                case TOKEN_AND:
                case TOKEN_OR:
                    newnode->left = current->right;
                    newnode->left->parent = newnode;
                    newnode->parent = current;
                    current = current->right = newnode;
                    continue;

                default:
                    break;
                }
            }
            break;

        case TOKEN_RBRACE:
            while (current && current->token.type != TOKEN_LBRACE) {
                current = current->parent;
            }

            if (current) {
                TYPE_TOKEN(&current->token, TOKEN_GROUP);
                continue;
            }

            error = "Unmatched ')' in \"%s\" in file %s";
            break;

        case TOKEN_NOT:
        case TOKEN_LBRACE:
            switch (current->token.type) {
            case TOKEN_STRING:
            case TOKEN_RE:
            case TOKEN_RBRACE:
            case TOKEN_GROUP:
                break;

            default:
                current->right = newnode;
                newnode->parent = current;
                current = newnode;
                continue;
            }
            break;

        default:
            break;
        }

        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, error, expr, r->filename);
        was_error = 1;
                return sctx->cond->condition ;
        return 0;
    }

    DEBUG_DUMP_TREE(ctx, root);

    /* Evaluate Parse Tree */
    current = root;
    error = NULL;
    while (current) {
        switch (current->token.type) {
        case TOKEN_STRING:
            current->value = !!*current->token.value;
            break;

        case TOKEN_AND:
        case TOKEN_OR:
            if (!current->left || !current->right) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression \"%s\" in file %s",
                              expr, r->filename);
                was_error = 1;
                return sctx->cond->condition ;
                return 0;
            }

            if (!current->left->done) {
                switch (current->left->token.type) {
                case TOKEN_STRING:
                    current->left->value = !!*current->left->token.value;
                    DEBUG_DUMP_EVAL(ctx, current->left);
                    current->left->done = 1;
                    break;

                default:
                    current = current->left;
                    continue;
                }
            }

            /* short circuit evaluation */
            if (!current->right->done && !regex &&
                ((current->token.type == TOKEN_AND && !current->left->value) ||
                (current->token.type == TOKEN_OR && current->left->value))) {
                current->value = current->left->value;
            }
            else {
                if (!current->right->done) {
                    switch (current->right->token.type) {
                    case TOKEN_STRING:
                        current->right->value = !!*current->right->token.value;
                        DEBUG_DUMP_EVAL(ctx, current->right);
                        current->right->done = 1;
                        break;

                    default:
                        current = current->right;
                        continue;
                    }
                }

                if (current->token.type == TOKEN_AND) {
                    current->value = current->left->value &&
                                     current->right->value;
                }
                else {
                    current->value = current->left->value ||
                                     current->right->value;
                }
            }
            break;

        case TOKEN_EQ:
        case TOKEN_NE:
            if (!current->left || !current->right ||
                current->left->token.type != TOKEN_STRING ||
                (current->right->token.type != TOKEN_STRING &&
                 current->right->token.type != TOKEN_RE)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Invalid expression \"%s\" in file %s",
                            expr, r->filename);
                was_error = 1;
                return sctx->cond->condition ;
                return 0;
            }

            if (current->right->token.type == TOKEN_RE) {
/*
                current->value = re_check(ctx, sctx,
			current->left->token.value,
                                          current->right->token.value);
*/
		/* FIXME -  NOTIMPL */
                was_error = 1;
                return sctx->cond->condition ;
                --regex;
            }
            else {
                current->value = !strcmp(current->left->token.value,
                                         current->right->token.value);
            }

            if (current->token.type == TOKEN_NE) {
                current->value = !current->value;
            }
            break;

        case TOKEN_GE:
        case TOKEN_GT:
        case TOKEN_LE:
        case TOKEN_LT:
            if (!current->left || !current->right ||
                current->left->token.type != TOKEN_STRING ||
                current->right->token.type != TOKEN_STRING) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Invalid expression \"%s\" in file %s",
                              expr, r->filename);
                was_error = 1;
                return sctx->cond->condition ;
                return 0;
            }


            current->value = strcmp(current->left->token.value,
                                    current->right->token.value);

            switch (current->token.type) {
            case TOKEN_GE: current->value = current->value >= 0; break;
            case TOKEN_GT: current->value = current->value >  0; break;
            case TOKEN_LE: current->value = current->value <= 0; break;
            case TOKEN_LT: current->value = current->value <  0; break;
            default: current->value = 0; break; /* should not happen */
            }
            break;

        case TOKEN_NOT:
        case TOKEN_GROUP:
            if (current->right) {
                if (!current->right->done) {
                    current = current->right;
                    continue;
                }
                current->value = current->right->value;
            }
            else {
                current->value = 1;
            }

            if (current->token.type == TOKEN_NOT) {
                current->value = !current->value;
            }
            break;

        case TOKEN_RE:
            if (!error) {
                error = "No operator before regex in expr \"%s\" in file %s";
            }
        case TOKEN_LBRACE:
            if (!error) {
                error = "Unmatched '(' in \"%s\" in file %s";
            }
        default:
            if (!error) {
                error = "internal parser error in \"%s\" in file %s";
            }

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, error, expr,r->filename);
            was_error = 1;
                return sctx->cond->condition ;
            return 0;
        }

        DEBUG_DUMP_EVAL(ctx, current);
        current->done = 1;
        current = current->parent;
    }

    return (root ? root->value : 0) ? IF_MATCH : IF_UNSATISFIED ;
}


static int find_file(request_rec *r, const char *fname,
	apr_file_t** file, apr_finfo_t *finfo, apr_int32_t flags) {
    apr_status_t rv = APR_SUCCESS;

    const char* slash = strrchr(r->filename, '/') ;
    const char* rootpath = apr_pstrndup(r->pool, r->filename, slash-r->filename) ;
    char* newpath = NULL ;

    rv = apr_filepath_merge(&newpath, rootpath, fname,
	APR_FILEPATH_NOTABOVEROOT, r->pool) ;
    if ( rv != APR_SUCCESS )
      return -1 ;

    rv = apr_file_open(file, newpath, APR_READ|APR_SENDFILE_ENABLED,
	APR_OS_DEFAULT, r->pool) ;

    if ( rv != APR_SUCCESS )
      return -1 ;

    if ( flags != 0 ) {
      rv = apr_file_info_get(finfo, flags, *file) ;
      if ( rv != APR_SUCCESS )
        return -1 ;
    }

    return 0 ;
}


static int find_virtual(request_rec *r, const char *fname, apr_finfo_t *finfo) {
        /* note: it is okay to pass NULL for the "next filter" since
           we never attempt to "run" this sub request. */
  request_rec* rr = ap_sub_req_lookup_uri(fname, r, NULL);
  if ( ! rr )
    return -1 ;

  if (rr->status == HTTP_OK && rr->finfo.filetype != 0) {
     memcpy((char *) finfo, (const char *) &rr->finfo,
                   sizeof(rr->finfo));
     ap_destroy_sub_req(rr);
     return 0;
  }
  ap_destroy_sub_req(rr);
  return -1;
}
#define add_include_vars_lazy(r,var)
#define PARSE_STRING_INITIAL_SIZE 64
/* taken from mod_include and purged of some redundancy */
static char* ap_ssi_parse_string(request_rec *r, const char *in) {
    apr_size_t length = MAX_STRING_LEN ;
    char* out ;
    char ch;
    char *next;
    char *end_out;
    apr_size_t out_size;

    /* allocate an output buffer if needed */
    out_size = PARSE_STRING_INITIAL_SIZE;
    if (out_size > length) {
        out_size = length;
    }
    out = apr_palloc(r->pool, out_size);

    /* leave room for nul terminator */
    end_out = out + out_size - 1;

    next = out;
    while ((ch = *in++) != '\0') {
        switch (ch) {
        case '\\':
            if (next == end_out) {
                if (out_size < length) {
                    /* double the buffer size */
                    apr_size_t new_out_size = out_size * 2;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                else {
                    /* truncated */
                    *next = '\0';
                    return out;
                }
            }
            if (*in == '$') {
                *next++ = *in++;
            }
            else {
                *next++ = ch;
            }
            break;
        case '$':
            {
                const char *start_of_var_name;
                char *end_of_var_name;        /* end of var name + 1 */
                const char *expansion, *temp_end, *val;
                char        tmp_store;
                apr_size_t l;

                /* guess that the expansion won't happen */
                expansion = in - 1;
                if (*in == '{'  /* } */ ) {
                    ++in;
                    start_of_var_name = in;
/*{*/               in = ap_strchr_c(in, '}');
                    if (in == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR,
/*{*/                                 0, r, "Missing '}' on variable \"%s\"",
                                      expansion);
                        *next = '\0';
                        return out;
                    }
                    temp_end = in;
                    end_of_var_name = (char *)temp_end;
                    ++in;
                }
                else {
                    start_of_var_name = in;
                    while (isalnum(*in) || *in == '_') {
                        ++in;
                    }
                    temp_end = in;
                    end_of_var_name = (char *)temp_end;
                }
                /* what a pain, too bad there's no table_getn where you can
                 * pass a non-nul terminated string */
                l = end_of_var_name - start_of_var_name;
                if (l != 0) {
                    tmp_store        = *end_of_var_name;
                    *end_of_var_name = '\0';
                    val = apr_table_get(r->subprocess_env, start_of_var_name);
                    *end_of_var_name = tmp_store;

                    if (val) {
                        expansion = val;
                        l = strlen(expansion);
                    }
                    else {
                        /* no expansion to be done */
                        break;
                    }
                }
                else {
                    /* zero-length variable name causes just the $ to be
                     * copied */
                    l = 1;
                }
                if ((next + l > end_out) && (out_size < length)) {
                    /* increase the buffer size to accommodate l more chars */
                    apr_size_t new_out_size = out_size;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    do {
                        new_out_size *= 2;
                    } while (new_out_size < current_length + l);
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                l = ((int)l > end_out - next) ? (end_out - next) : l;
                memcpy(next, expansion, l);
                next += l;
                break;
            }
        default:
            if (next == end_out) {
                if (out_size < length) {
                    /* double the buffer size */
                    apr_size_t new_out_size = out_size * 2;
                    apr_size_t current_length = next - out;
                    char *new_out;
                    if (new_out_size > length) {
                        new_out_size = length;
                    }
                    new_out = apr_palloc(r->pool, new_out_size);
                    memcpy(new_out, out, current_length);
                    out = new_out;
                    out_size = new_out_size;
                    end_out = out + out_size - 1;
                    next = out + current_length;
                }
                else {
                    /* truncated */
                    *next = '\0';
                    return out;
                }
            }
            *next++ = ch;
            break;
        }
    }
    *next = '\0';
    return out;

}

typedef struct {
  const char* name ;
  int (*func)(xmlns_public* ctx, ssi_ctx*) ;
} ssi_handler ;

static int ssi_eval_cond(ssi_ctx* sctx) {
  ssi_condition* cond ;
  for ( cond = sctx->cond ; cond ; cond = cond->parent )
    if ( cond->condition != IF_MATCH )
      return 1 ;
  return 0 ;
}
#define ssi_onoff(x,y) xmlns_suppress_output(x, y)

static int ssi_if(xmlns_public* ctx, ssi_ctx* sctx) {
  int after ;
  int before = ssi_eval_cond(sctx) ;
  ssi_condition* cond = apr_pcalloc(ctx->f->r->pool, sizeof(ssi_condition) ) ;
  cond->condition = IF_UNSATISFIED ;
  cond->parent = sctx->cond ;
  sctx->cond = cond ;
  cond->condition = test_condition(ctx, sctx) ;
  after = ssi_eval_cond(sctx) ;
  if ( after != before )
    ssi_onoff(ctx, after) ;
  return OK ;
}
static int ssi_else(xmlns_public* ctx, ssi_ctx* sctx) {
  int after ;
  int before = ssi_eval_cond(sctx) ;
  if ( !sctx->cond )
    return DECLINED ;
  if ( sctx->cond->condition == IF_UNSATISFIED )
    sctx->cond->condition = IF_MATCH ;
  else
    sctx->cond->condition = IF_SATISFIED ;
  after = ssi_eval_cond(sctx) ;
  if ( after != before )
    ssi_onoff(ctx, after) ;
  return OK ;
}
static int ssi_elif(xmlns_public* ctx, ssi_ctx* sctx) {
  int after ;
  int before = ssi_eval_cond(sctx) ;
  if ( !sctx->cond )
    return DECLINED ;
  if ( sctx->cond->condition == IF_UNSATISFIED )
    sctx->cond->condition = test_condition(ctx, sctx) ;
  else if ( sctx->cond->condition == IF_MATCH )
    sctx->cond->condition = IF_SATISFIED ;
  after = ssi_eval_cond(sctx) ;
  if ( after != before )
    ssi_onoff(ctx, after) ;
  return OK ;
}
static int ssi_endif(xmlns_public* ctx, ssi_ctx* sctx) {
  int after ;
  int before = ssi_eval_cond(sctx) ;
  if ( !sctx->cond )
    return DECLINED ;
  sctx->cond = sctx->cond->parent ;
  after = ssi_eval_cond(sctx) ;
  if ( after != before )
    ssi_onoff(ctx, after) ;
  return OK ;
}
#define BUFSZ 4096
static int ssi_include(xmlns_public* ctx, ssi_ctx* sctx) {
  int res ;
  request_rec* rr ;
  const char* uri = apr_table_get(sctx->args, "file") ;
  apr_file_t* file ;
  apr_finfo_t finfo ;
  if ( uri ) {
    res = find_file(ctx->f->r, uri, &file, &finfo, APR_FINFO_SIZE) ;
    if ( res )
      return DECLINED ;
    ap_pass_brigade(ctx->f->next, ctx->bb) ;
    apr_brigade_cleanup(ctx->bb) ;
    APR_BRIGADE_INSERT_TAIL(ctx->bb, apr_bucket_file_create(file, 0,
	finfo.size, ctx->f->r->pool, ctx->f->r->connection->bucket_alloc) ) ;

    return OK ;
  }
  uri = apr_table_get(sctx->args, "virtual") ;
  if ( !uri )
    return OK ;
  rr = ap_sub_req_lookup_uri(uri, ctx->f->r, ctx->f->next);
  if ( !rr ) {
    return DECLINED ;
  }
  apr_pool_cleanup_register(ctx->f->r->pool, rr,
	(void*)ap_destroy_sub_req, apr_pool_cleanup_null) ;
  if ( rr->status != HTTP_OK || !rr->content_type
	|| strncasecmp(rr->content_type, "text/", 5) ) {
    return DECLINED ;
  }
  ap_pass_brigade(ctx->f->next, ctx->bb) ;
  apr_brigade_cleanup(ctx->bb) ;
  ap_set_module_config(rr->request_config, &xhtml_module, ctx->f->r);
  res = ap_run_sub_req(rr) ;
  return OK ;
}
static int ssi_config(xmlns_public* ctx, ssi_ctx* sctx) {
  const char* errmsg = apr_table_get(sctx->args, "errmsg") ;
  const char* sizefmt = apr_table_get(sctx->args, "sizefmt") ;
  const char* timefmt = apr_table_get(sctx->args, "timefmt") ;
  request_rec* r = ctx->f->r ;
  apr_table_t* env = r->subprocess_env ;
  if ( errmsg )
    sctx->errmsg = apr_pstrdup(ctx->f->r->pool, errmsg) ;
  if ( timefmt ) {
    sctx->timefmt = apr_pstrdup(ctx->f->r->pool, timefmt) ;
#if 1
    apr_table_setn(env, "DATE_LOCAL", ap_ht_time(r->pool, r->request_time,
                               timefmt, 0));
    apr_table_setn(env, "DATE_GMT", ap_ht_time(r->pool, r->request_time,
                               timefmt, 1));
    apr_table_setn(env, "LAST_MODIFIED",
	ap_ht_time(r->pool, r->finfo.mtime, timefmt, 0));
#endif
  }
  if ( sizefmt ) {
    if ( !strcasecmp(sizefmt, "bytes") )
      sctx->sizefmt = SIZEFMT_BYTES ;
    else if ( !strcasecmp(sizefmt, "abbrev") )
      sctx->sizefmt = SIZEFMT_ABBREV ;
  }
  return OK ;
}
static int ssi_set(xmlns_public* ctx, ssi_ctx* sctx) {
  const char* var = apr_table_get(sctx->args, "var") ;
  const char* val = apr_table_get(sctx->args, "value") ;
  if ( var && val )
    apr_table_set(ctx->f->r->subprocess_env, var, val) ;
  return OK ;
}
static int ssi_echo(xmlns_public* ctx, ssi_ctx* sctx) {
  enum { ENC_NONE, ENC_ENTITY, ENC_URL } encoding = ENC_ENTITY ;
  const char* var = apr_table_get(sctx->args, "var") ;
  const char* enc ;
  const char* val ;
  /* FIXME - need to deal with things like dateformat; special vars */
  if ( !var ) {
    return DECLINED ;
  }
  if ( val = apr_table_get(ctx->f->r->subprocess_env, var), !val ) {
      return OK ;
  }
  if ( enc = apr_table_get(sctx->args, "encoding"), enc ) {
    if ( !strcasecmp(enc, "url") )
      encoding = ENC_URL ;
    else if ( !strcasecmp(enc, "none") )
      encoding = ENC_NONE ;
  }
  switch ( encoding ) {
    case ENC_NONE:
      ap_fputs(ctx->f->next, ctx->bb, val) ;
      break ;
    case ENC_ENTITY:
      ap_fputs(ctx->f->next, ctx->bb, ap_escape_html(ctx->f->r->pool, val) ) ;
      break ;
    case ENC_URL:
      ap_fputs(ctx->f->next, ctx->bb, ap_escape_uri(ctx->f->r->pool, val) ) ;
      break ;
  }
  return OK ;
}
static int ssi_flastmod(xmlns_public* ctx, ssi_ctx* sctx) {
  const char* fname = apr_table_get(sctx->args, "file") ;
  apr_finfo_t finfo ;
  apr_file_t* file ;
  int error = 0 ;
  if ( fname )
    error = find_file(ctx->f->r, fname, &file, &finfo, APR_FINFO_MTIME) ;
  else if ( fname = apr_table_get(sctx->args, "virtual"), fname )
    error = find_virtual(ctx->f->r, fname, &finfo) ;
  if ( error )
    return DECLINED ;

  ap_fputs(ctx->f->next, ctx->bb,
	ap_ht_time(ctx->f->r->pool, finfo.mtime, sctx->timefmt, 0));
  return OK ;
}
static int ssi_fsize(xmlns_public* ctx, ssi_ctx* sctx) {
  const char* fname = apr_table_get(sctx->args, "file") ;
  apr_finfo_t finfo ;
  apr_file_t* file = NULL ;
  int error = 0 ;
  char buf[6] ;
  if ( fname )
    error = find_file(ctx->f->r, fname, &file, &finfo, APR_FINFO_SIZE) ;
  else if ( fname = apr_table_get(sctx->args, "virtual"), fname )
    error = find_virtual(ctx->f->r, fname, &finfo) ;

  if ( error ) {
    return DECLINED ;
  }
  switch ( sctx->sizefmt ) {
    case SIZEFMT_ABBREV:
      ap_fputs(ctx->f->next, ctx->bb, apr_strfsize(finfo.size, buf)) ;
      break ;
    case SIZEFMT_BYTES:
      ap_fputs(ctx->f->next, ctx->bb, apr_psprintf(ctx->f->r->pool, "%d", (int)finfo.size)) ;
      break ;
  }
  return OK ;
}
static int printitem(void* rec, const char* key, const char* value) {
  xmlns_public* ctx = rec ;
  ap_fputstrs(ctx->f->next, ctx->bb, key, "=",
	ap_escape_html(ctx->f->r->pool, value) , "\n", NULL) ;
  return 1 ;
}
static int ssi_printenv(xmlns_public* ctx, ssi_ctx* sctx) {
  apr_table_do(printitem, ctx, ctx->f->r->subprocess_env, NULL) ;
  return OK ;
}

static apr_table_t* ssi_parseargs(request_rec* r, const xmlns_attr_t* attrs,
	apr_table_t* results) {
  int i ;
  const xml_char_t* key ;
  const xml_char_t* val ;
  apr_table_clear(results) ;
  for ( i = 0 ; ; ++i ) {
    key = xmlns_get_attr_name(attrs, i) ;
    if ( ! key )
      break ;
    val = xmlns_get_attr_val(attrs, i) ;
    apr_table_setn(results, key, val) ;
  } ;
  return results ;
}
static apr_table_t* ssi_parse(request_rec* r, const xml_char_t* chars, apr_table_t* results) {
  apr_pool_t* pool = r->pool ;
  char quot = '"' ;
  const xml_char_t* p = chars ;
  const xml_char_t* q ;
  apr_table_clear(results) ;
  char* var ;
  char* val ;
  while ( *p ) {
    while ( isspace(*p) )
      ++p ;
    if ( ! *p )
      break ;
    var = val = NULL ;
    q = p + strcspn(p, "= 	\r\n") ;
    var = apr_pstrndup(pool, p, q-p) ;
    while ( isspace(*q) )
      ++q ;
    if ( *q != '=' )
      break ;
    p = q + 1 ;
    while ( isspace(*p) )
      ++p ;
    switch ( *p ) {
      case 0:
	break ;
      case '"':
      case '\'':
        quot = *p++ ;
	q = strchr(p, quot) ;
	if ( q > p )
	  val = apr_pstrndup(pool, p, q-p) ;
	break ;
      default:
	q = p + strcspn(p, " 	\r\n") ;
	if ( q > p )
	  val = apr_pstrndup(pool, p, q-p) ;
	else
	  val = apr_pstrdup(pool, p) ;
	break ;
    }
    if ( !var || !val ) {
	/* error */
	return NULL ;
    }
    apr_table_setn(results, var, ap_ssi_parse_string(r, val)) ;
    p = q+1 ;
  }
  return results ;
}
static ssi_handler cond_handlers[] = {
  { "if", ssi_if } ,
  { "else", ssi_else } ,
  { "elif", ssi_elif } ,
  { "endif", ssi_endif } ,
  { NULL, NULL }
} ;
static ssi_handler gen_handlers[] = {
  { "set", ssi_set } ,
  { "config", ssi_config } ,
  { "include", ssi_include } ,
  { "flastmod", ssi_flastmod } ,
  { "echo", ssi_echo } ,
  { "fsize", ssi_fsize } ,
  { "printenv", ssi_printenv } ,
  { NULL, NULL }
} ;
static int ssi_end(xmlns_public* ctx, const parsedname* name3) {
  return OK ;
}
static int ssi_start(xmlns_public* ctx,
	const parsedname* name3, const xmlns_attr_t* atts) {
  ssi_handler* handler ;
  ssi_condition* cond ;
  ssi_ctx* sctx = ap_get_module_config(ctx->f->r->request_config, &xhtml_module);
  for ( handler = cond_handlers ; handler->name != NULL ; ++handler ) {
    if ( !strncmp(handler->name, name3->elt, name3->eltlen) ) {
      sctx->args = ssi_parseargs(ctx->f->r, atts, sctx->args) ;
      if ( sctx->args ) {
        if ( handler->func(ctx, sctx) != OK ) {
	  ap_fputs(ctx->f->next, ctx->bb, sctx->errmsg) ;
	}
	return OK ;
      }
    }
  }
  for ( cond = sctx->cond ; cond ; cond = cond->parent )
    if ( cond->condition != IF_MATCH )
      return OK ;
  for ( handler = gen_handlers ; handler->name != NULL ; ++handler ) {
    if ( !strncmp(handler->name, name3->elt, name3->eltlen) ) {
      sctx->args = ssi_parseargs(ctx->f->r, atts, sctx->args) ;
      if ( sctx->args ) {
        if ( handler->func(ctx, sctx) != OK ) {
	  ap_fputs(ctx->f->next, ctx->bb, sctx->errmsg) ;
	}
	return OK ;
      }
    }
  }
  return OK ;
}
static int ssi_comment(xmlns_public* ctx, const xml_char_t* chars) {
  size_t len ;
  ssi_handler* handler ;
/* split up the handlers so that if we're inside an IF that
   evaluated to false (or an ELSE or ELIF to one that was true)
   then we only evaluate conditionals themselves.
*/
  ssi_ctx* sctx = ap_get_module_config(ctx->f->r->request_config, &xhtml_module);
  ssi_condition* cond ;
  for ( handler = cond_handlers ; handler->name != NULL ; ++handler ) {
    len = strlen(handler->name) ;
    if ( !strncmp(handler->name, chars+1, len) ) {
      sctx->args = ssi_parse(ctx->f->r, chars+len+2, sctx->args) ;
      if ( sctx->args ) {
        if ( handler->func(ctx, sctx) != OK ) {
	  ap_fputs(ctx->f->next, ctx->bb, sctx->errmsg) ;
	}
	return OK ;
      }
    }
  }
  for ( cond = sctx->cond ; cond ; cond = cond->parent )
    if ( cond->condition != IF_MATCH )
      return OK ;
  for ( handler = gen_handlers ; handler->name != NULL ; ++handler ) {
    len = strlen(handler->name) ;
    if ( !strncmp(handler->name, chars+1, len) ) {
      sctx->args = ssi_parse(ctx->f->r, chars+len+2, sctx->args) ;
      if ( sctx->args ) {
        if ( handler->func(ctx, sctx) != OK ) {
	  ap_fputs(ctx->f->next, ctx->bb, sctx->errmsg) ;
	}
	return OK ;
      }
    }
  }
  ap_fputs(ctx->f->next, ctx->bb, sctx->errmsg) ;
  return OK ;
}
static void add_include_vars(request_rec* r, const char* timefmt) {
    apr_table_t *e = r->subprocess_env;
    char *t;

    apr_table_setn(e, "DATE_LOCAL",
	ap_ht_time(r->pool, r->request_time, timefmt, 0));
    apr_table_setn(e, "DATE_GMT",
	ap_ht_time(r->pool, r->request_time, timefmt, 1));
    apr_table_setn(e, "LAST_MODIFIED",
	ap_ht_time(r->pool, r->finfo.mtime, timefmt, 0));
    if ( apr_uid_name_get(&t, r->finfo.user, r->pool) != APR_SUCCESS)
      t = "<unknown>" ;
    apr_table_setn(e, "USER_NAME", t);

    apr_table_setn(e, "DOCUMENT_URI", r->uri);
    if (r->path_info && *r->path_info) {
        apr_table_setn(e, "DOCUMENT_PATH_INFO", r->path_info);
    }
    if (r->filename && (t = strrchr(r->filename, '/'))) {
        apr_table_setn(e, "DOCUMENT_NAME", ++t);
    }
    else {
        apr_table_setn(e, "DOCUMENT_NAME", r->uri);
    }
    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        ap_unescape_url(arg_copy);
        apr_table_setn(e, "QUERY_STRING_UNESCAPED",
                  ap_escape_shell_cmd(r->pool, arg_copy));
    }

}
static void ssi_init(xmlns_public* ctx, const xml_char_t* prefix,
	const xml_char_t* uri) {
  request_rec* r = ctx->f->r ;
  xhtml_conf* conf = ap_get_module_config(r->per_dir_config, &xhtml_module);
/* check this in case we get called both by xhtml and ssi namespaces */
  ssi_ctx* sctx = ap_get_module_config(ctx->f->r->request_config, &xhtml_module);
  if ( sctx ) {
    if ( sctx->refcount++ )
      return ;
  } else {
    sctx = apr_pcalloc(r->pool, sizeof(ssi_ctx)) ;
    //xmlns_set_appdata(ctx, &xhtml_module, sctx) ;
    ap_set_module_config(ctx->f->r->request_config, &xhtml_module, sctx) ;
    sctx->args = apr_table_make(r->pool, 2) ;
    sctx->refcount = 1 ;

    ap_add_common_vars(r) ;
    ap_add_cgi_vars(r) ;
    add_include_vars(r, conf->timefmt) ;
  }
  sctx->errmsg = conf->errmsg ;
  sctx->timefmt = conf->timefmt ;
  sctx->sizefmt = conf->sizefmt ;
}
static void ssi_term(xmlns_public* ctx, const xml_char_t* foo) {
  ssi_ctx* sctx = ap_get_module_config(ctx->f->r->request_config, &xhtml_module);
  --sctx->refcount ;
}
static xmlns xmlns_xhtml_ssi = {
  XMLNS_VERSION,
  xhtml_start ,		/* StartElement	*/
  xhtml_end ,		/* EndElement	*/
  ssi_init ,		/* StartNSDecl	*/
  ssi_term ,		/* EndNSDecl	*/
  "#" ,			/* Comment Identifier (should be "#") */
  ssi_comment,		/* Comment Handler */
  NULL,
  NULL
} ;
static xmlns xmlns_ssi = {
  XMLNS_VERSION,
  ssi_start ,		/* StartElement	*/
  ssi_end ,		/* EndElement	*/
  ssi_init ,		/* StartNSDecl	*/
  ssi_term ,		/* EndNSDecl	*/
  NULL ,		/* Comment Identifier (should be "#") */
  NULL,			/* Comment Handler */
  NULL,
  NULL
} ;
static xmlns xmlns_xhtml10 = {
  XMLNS_VERSION,
  xhtml_start ,		/* StartElement	*/
  xhtml_end ,		/* EndElement	*/
  NULL ,		/* StartNSDecl	*/
  NULL ,		/* EndNSDecl	*/
  NULL ,		/* Comment Identifier (should be "#") */
  NULL,			/* Comment Handler */
  NULL,
  NULL
} ;

static void xhtml_hooks(apr_pool_t* pool) {
  ap_register_provider(pool, "xmlns", XHTML10 , "1.0", &xmlns_xhtml10) ;
  ap_register_provider(pool, "xmlns", XHTML10 , "ssi", &xmlns_xhtml_ssi) ;
  ap_register_provider(pool, "xmlns", SSI , "ssi", &xmlns_ssi) ;
  ap_hook_optional_fn_retrieve(xmlns_funcs, NULL, NULL, APR_HOOK_MIDDLE);
}
static const char* set_sizefmt(cmd_parms *cmd, void *cfg, const char* sizefmt) {
  if ( sizefmt ) {
    if ( !strcasecmp(sizefmt, "bytes") )
      ((xhtml_conf*)(cfg))->sizefmt = SIZEFMT_BYTES ;
    else if ( !strcasecmp(sizefmt, "abbrev") )
      ((xhtml_conf*)(cfg))->sizefmt = SIZEFMT_ABBREV ;
  }
  return NULL ;
}
static const command_rec xhtml_cmds[] = {
  AP_INIT_TAKE1("XHTMLSSIerrmsg", ap_set_string_slot,
	(void*)APR_OFFSETOF(xhtml_conf, errmsg), OR_ALL,
	"default error msg") ,
  AP_INIT_TAKE1("XHTMLSSItimefmt", ap_set_string_slot,
	(void*)APR_OFFSETOF(xhtml_conf, timefmt), OR_ALL,
	"default time format") ,
  AP_INIT_TAKE1("XHTMLSSIsizefmt", set_sizefmt, NULL, OR_ALL,
	"default size format") ,
  { NULL }
} ;
static void* xhtml_cr_conf(apr_pool_t* p, char* x) {
  xhtml_conf* ret = apr_palloc(p, sizeof(xhtml_conf)) ;
  ret->sizefmt = SIZEFMT_ABBREV ;
  ret->errmsg = "[An error occurred while processing this directive]" ;
  ret->timefmt = "%A, %d-%b-%Y %H:%M:%S %Z" ;
  return ret ;
}

module AP_MODULE_DECLARE_DATA xhtml_module = {
	STANDARD20_MODULE_STUFF,
	xhtml_cr_conf,
	NULL,
	NULL,
	NULL,
	xhtml_cmds,
	xhtml_hooks
} ;
