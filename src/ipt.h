#ifndef IPT_H
#define IPT_H

#include <stddef.h>

typedef struct{
    int num;
    int pkts;
    char* prot;

    char* target;
    char* src;
    char* dst;

    int sport;
    int dport;
}Rule;

typedef struct{
    Rule *items;
    size_t count;
    size_t capacity;
}Rules;

// Macros

#define LOG(msg) fprintf(stderr, msg "\n")

#define do_cmd(cmd)\
    do{\
        if(system(cmd)){\
            fprintf(stderr, "do_cmd");\
        }\
    }while(0)

#define sudo_cmd(cmd)\
    do{\
        char _buf[1048];\
        snprintf(_buf, sizeof(_buf), "sudo %s", cmd);\
        do_cmd(_buf);\
    }while(0)

#define da_append(da, x)\
    do{\
        if(da.count >= da.capacity){\
            if (da.capacity == 0) da.capacity = 256;\
            else da.capacity *= 2;\
            da.items = realloc(da.items, da.capacity*sizeof(*da.items));\
        }\
        da.items[da.count++] = x;\
    }while(0)

// If dst.count = 0, dumps src to dst.
#define da_dump(dst, src)\
    do{\
        if (dst.count <= 0) {\
            dst.capacity = src.capacity;\
            dst.count = src.count;\
            dst.items = malloc(src.capacity*sizeof(*(src.items)));\
            dst.items = memcpy(dst.items, src.items, src.count*sizeof(*(src.items)));\
        }\
    }while(0)

#define da_free(da)\
    do{\
        free(da.items);\
    }while(0)\


void print_rule(Rule rule);
void print_rules(const Rules* rules);

int parse_rules_from_file(char* filename, Rules* rules);
void str_trim(char* str);
bool is_valid_ipv4_or_cidr(const char* s);

void ipt_save_rule_listing_to_file(const char* filename);
void ipt_insert_new_rule(int num, const char* src, const char* dst,
        const char* prot, int sport, int dport, const char* target);

void ipt_whitelist_ips(const char* ips);
void ipt_blacklist_ips(const char* ips);

void ipt_delete_rule(int num);
void ipt_replace_rule(int num, const char* src, const char* dst,
        const char* prot, int sport, int dport, const char* target);

void ipt_reorder(const Rules* dst);

#endif /* ifndef IPT_H */
