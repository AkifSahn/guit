#ifndef PARSER_H
#define PARSER_H

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
            abort();\
        }\
    }while(0)

#define sudo_cmd(cmd) do_cmd("sudo " cmd)

#define da_append(da, x)\
    do{\
        if(da.count >= da.capacity){\
            if (da.capacity == 0) da.capacity = 256;\
            else da.capacity *= 2;\
            da.items = realloc(da.items, da.capacity*sizeof(*da.items));\
        }\
        da.items[da.count++] = x;\
    }while(0)

#define da_free(da)\
    do{\
        free(da.items);\
    }while(0)\


int parse_rules_from_file(char* filename, Rules* rules);

#endif /* ifndef PARSER_H */
