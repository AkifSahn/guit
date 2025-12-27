#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ipt.h"

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

void str_trim(char* str){
    char *start = str;
    char *end;

    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    if (*start == '\0') {
        str[0] = '\0';
        return;
    }

    end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }

    *(end + 1) = '\0';

    if (start != str) {
        memmove(str, start, (end - start + 2));
    }
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

bool is_valid_ipv4_or_cidr(const char* s){
    const char* p = s;
    int octet = 0, octet_count = 0, digit_count = 0;

    // Parse 4 octets
    for (;;) {
        octet = 0;
        digit_count = 0;
        while (isdigit(*p)) {
            octet = octet*10 + (*p - '0');
            digit_count++;
            p++;
            if (digit_count == 3) break;
        }

        if (octet < 0 || octet > 255) return false;
        octet_count++;

        if (octet_count == 4) break;
        if (*p != '.') return false;
        p++;
    }

    // We are done, or '/'
    if (*p == '\0') return true;
    if (*p != '/') return false;
    p++;

    int val = 0;
    digit_count = 0;
    while (isdigit(*p)) {
        val = val*10 + (*p - '0');
        p++;
        digit_count++;
        if (digit_count == 2) break;
    }
    
    if (*p != '\0') return false;
    if (val >= 0 && val <= 32) return true;

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

static int parse_rule_from_line(const char* line, Rules* rules){
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
    if (f == NULL) {
        fprintf(stderr, "Failed to open file `%s`: %s\n", filename, strerror(errno));
        exit(1);
    }

    char *buffer = NULL;
    size_t buffer_size;
    ssize_t n;
    while ((n = getline(&buffer, &buffer_size, f)) != -1) {
        parse_rule_from_line(buffer, rules);
    }

    if (ferror(f)) {
        fprintf(stderr, "Failed to read file `%s`: %s\n", filename, strerror(errno));
        free(buffer);
        exit(1);
    }

    free(buffer);
    fclose(f);

    return 0;
}

int ipt_run(char* const args[]){
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        execvp(args[0], args);
        exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    return status;
}

/*
 * Calls `execvp` with given args in a new fork.
 * Returns 0 on succes, non-zero on failure.
 * 
 */
int ipt_run_to_file(const char* filename, char* const args[]) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            perror("open");
            exit(1);
        }

        dup2(fd, STDOUT_FILENO);

        close(fd);
        execvp(args[0], args);
        exit(0);
    }

    int status;
    waitpid(pid, &status, 0);
    return status;
}



// Saves iptables rule listings to a file.
void ipt_save_rule_listing_to_file(const char* filename){
    char* const args[] = {
        "sudo", "iptables",
        "-L", "INPUT", "-nv",
        "--line-numbers",
        NULL };

    if (ipt_run_to_file(filename, args) != 0){
        exit(1);
    }
}

void ipt_insert_new_rule(int num, const char* src, const char* dst,
        const char* prot, int sport, int dport, const char* target)
{
    char* args[50] = {
        "sudo", "iptables",
        "-I", "INPUT"}; 
    int i = 4;

    char *num_arg = NULL;
    char *sport_arg = NULL;
    char *dport_arg = NULL;

    char buffer[128];
    sprintf(buffer, "%d", num);
    num_arg = strdup(buffer);
    args[i++] = num_arg;


    if (*src){
        args[i++] = "-s";
        args[i++] = (char*)src;
    }

    if (*dst){
        args[i++] = "-d";
        args[i++] = (char*)dst;
    }

    args[i++] = "-p";
    args[i++] = (char*)prot;

    if (!strcmp(prot, "tcp") || !strcmp(prot, "udp")){
        if (sport >= 0){
            args[i++] = "--sport";
            sprintf(buffer, "%d", sport);
            sport_arg = strdup(buffer);
            args[i++] = sport_arg;
        }
        if (dport >= 0){
            args[i++] = "--dport";
            sprintf(buffer, "%d", dport);
            dport_arg = strdup(buffer);
            args[i++] = dport_arg;
        }
    }

    if(*target){
        args[i++] = "-j";
        args[i++] = (char*)target;
    }

    args[i++] = NULL;

    if (ipt_run(args) != 0){
        fprintf(stderr, "ipt_inert_new_rule - failed to run iptables command:\n");
        for (int j = 0; j < i-1; j++) {
            fprintf(stderr, "%s ", args[j]);
        }
    }

    free(num_arg);
    if (sport_arg) free(sport_arg);
    if (dport_arg) free(dport_arg);
}
