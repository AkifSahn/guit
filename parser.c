#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"


// Forward declerations
static void parse_rule_from_line(char* line, Rules* rules);

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

static void parse_rule_from_line(char* line, Rules* rules){

    if (!(line[0] >= '0' && line[0] <= '9')) {
        return;
    }
    // Expected format of a line
    // <num> <pkts> <bytes> <target> <prot> <opt> <in> <out> <src> <dst> <sip:num> <dip:num>

    Rule rule = {0};
    char buffer[256], c = 0;
    int line_i = 0, buff_i = 0, word_count = 0;
    while (line[line_i+1] != '\0') {
        c = line[line_i++];
        if (c == ' ') {
            if (buff_i == 0) continue; // no word in the buffer

            buffer[buff_i] = '\0';
            buff_i = 0;
            // TODO: fix memory leak, the tmp is never getting freed for most of the cases
            char *tmp = strdup(buffer);
            switch (word_count++) {
                case 0:
                    rule.num = atoi(tmp);
                    free(tmp);
                    break;
                case 1:
                    rule.pkts = atoi(tmp);
                    free(tmp);
                    break;
                case 2:
                    break;
                case 3:
                    rule.target = tmp;
                    break;
                case 4:
                    rule.prot = tmp;
                    break;
                case 8:
                    rule.src = tmp;
                    break;
                case 9:
                    rule.dst = tmp;
                    break;
            }
            continue;
        }
        buffer[buff_i++] = c;
    }

    da_append((*rules), rule);
}
