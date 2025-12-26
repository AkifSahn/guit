#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"

// Enum members are ordered in token appearance order in:
// 'iptables -L INPUT -nv --line-numbers'
typedef enum{
    TOKEN_NUM,
    TOKEN_PKTS,
    TOKEN_BYTES,
    TOKEN_TARGET,
    TOKEN_PROT,
    TOKEN_OPT,
    TOKEN_IN,
    TOKEN_OUT,
    TOKEN_SRC,
    TOKEN_DST,
    TOKEN_MODULE, // Can be comment, tcp, udp etc
    TOKEN_MODULE_1, // dport:<port>, sport:<port> or flags:<flags>
    TOKEN_MODULE_2, 
    TOKEN_MODULE_3,
}Token_Type;

static char** split_str(const char* str, char delim, size_t* num_tokens){

    // 1st pass, count tokens
    char* tmp = strdup(str);
    char* dummy = strtok(tmp, &delim);

    int token_count = 0;
    while (dummy != NULL) {
        printf("%s\n", dummy);
        dummy = strtok(NULL, &delim);
        token_count++;
    }
    free(tmp);

    // 2nd pass, fill the arr
    char** arr = malloc((token_count)*(sizeof(char*)));
    char* copy = strdup(str);
    char* token = strtok(copy, &delim);

    int i = 0;
    while (token != NULL) {
        arr[i++] = strdup(token);
        token = strtok(NULL, &delim);
    }

    *num_tokens = token_count;
    free(copy);
    return arr;
}

static bool str_has_prefix(const char* str, const char* prefix){
    size_t len_str = strlen(str);
    size_t len_prefix = strlen(prefix);

    if (len_str < len_prefix) return false;

    for (size_t i = 0; i < len_prefix; ++i) {
        if (str[i] != prefix[i]) {
            return false;
        }
    }

    return true;
}

static char* protos[] = {
    "tcp", "udp", "udplite", "icmp", "icmpv6",
    "esp", "ah", "sctp", "mh", "all"
};

static bool is_valid_protocol(const char* proto_str){
    for (size_t i = 0; i < sizeof(protos)/sizeof(protos[0]); ++i) {
        if (!strcmp(protos[i], proto_str)) return true;
    }
    return false;
}

static void parse_module_token(Rule* rule, const char* token){
    size_t num_sub_tokens;
    char** sub_tokens = split_str(token, ':', &num_sub_tokens);
    if (num_sub_tokens == 2) {
        if (!strcmp(sub_tokens[0], "spt")) {
            rule->sport = atoi(sub_tokens[1]);
        }else if (!strcmp(sub_tokens[0], "dpt")) {
            rule->dport = atoi(sub_tokens[1]);
        }
    }

    for (size_t i = 0; i < num_sub_tokens; ++i) {
        free(sub_tokens[i]);
    }
    free(sub_tokens);
}

static int parse_rule_from_line(char* line, Rules* rules){
    if (str_has_prefix(line, "Chain") || str_has_prefix(line, "num")) {
        return 0;
    }

    size_t num_tokens;
    char** tokens = split_str(line, ' ', &num_tokens);

    Rule rule = {0};
    rule.sport = -1;
    rule.dport = -1;
    const char* token;
    for (size_t i = 0, tok_type = TOKEN_NUM; i < num_tokens; ++i, ++tok_type) {
        token = tokens[i];
        switch (tok_type) {
        case TOKEN_NUM:
            rule.num = atoi(token);
            break;
        case TOKEN_PKTS:
            rule.pkts = atoi(token);
            break;
        case TOKEN_BYTES:
            break;
        case TOKEN_TARGET:
            // Target may be empty, but protocol can not. Check if token is protocol.
            if (is_valid_protocol(token)) {
                rule.prot = strdup(token);
                tok_type = TOKEN_PROT;
                continue;
            }
            rule.target = strdup(token);
            break;
        case TOKEN_PROT:
            rule.prot = strdup(token);
            break;
        case TOKEN_OPT:
            break;
        case TOKEN_IN:
            break;
        case TOKEN_OUT:
            break;
        case TOKEN_SRC:
            rule.src = strdup(token);
            break;
        case TOKEN_DST:
            rule.dst = strdup(token);
            break;
        case TOKEN_MODULE:
            if (strcmp(token, "tcp")) {
                i = num_tokens;
            }
            break;
        case TOKEN_MODULE_1:
            parse_module_token(&rule, token);
            break;
        case TOKEN_MODULE_2: 
            parse_module_token(&rule, token);
            break;
        case TOKEN_MODULE_3:
            parse_module_token(&rule, token);
            break;
        default:
            // assert(0 || "parse_rule_from_line: Token Type not supported");
            fprintf(stderr, "unsupported token: '%s'\n", token);
            return 1;
        }
    }

    for (size_t i = 0; i < num_tokens; ++i) {
        free(tokens[i]);
    }
    free(tokens);
    da_append((*rules), rule);
    return 0;
}

int parse_rules_from_file(char* filename, Rules* rules){
    FILE* f = fopen(filename, "r");
    if (!f) {
        return 1;
    }

    char buffer[1024];
    char c;
    int i = 0;
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n') {
            buffer[i++] = '\0';
            // Parse the line
            parse_rule_from_line(buffer, rules);
            i = 0;
            continue;
        }
        buffer[i++] = c;
    }

    return 0;
}
