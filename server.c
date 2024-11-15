
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#define MAX_IP_LENGTH  16
#define MAX_PORT_LENGTH 6
#define MAX_RULE_LENGTH 256
#define BUFFERLENGTH 10000

int isExecuted = 0;

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

char *readRes(int sockfd);
int writeResult(int sockfd, char *buffer, size_t bufsize);
void store_request(const char *command);

typedef struct IPrange {
    char start[MAX_IP_LENGTH];
    char end[MAX_IP_LENGTH];
    int is_range;
} IPrange;

typedef struct PortRange {
    int start;
    int end;
    int is_range;
} PortRange;


typedef struct MatchedQuery {
    char ip[MAX_IP_LENGTH];
    int port;
    struct MatchedQuery *next;
} MatchedQuery;


typedef struct FirewallRule {
    IPrange ip_range;
    PortRange port_range;
    MatchedQuery *matched_queries;
   struct FirewallRule *next;
} FirewallRule;

typedef struct Request {
    char command_type;
    char command[MAX_RULE_LENGTH];
    struct Request *next;
} Request;


FirewallRule *rules_head = NULL; //linked list for firewall rules
Request *requests_head = NULL; // linked list for requests



int is_valid_ip(const char* ip) { // Validate IP address
    int a, b, c, d;
     return sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 &&
           a >= 0 && a <= 255 &&
           b >= 0 && b <= 255 &&
           c >= 0 && c <= 255 &&
           d >= 0 && d <= 255;
}

int is_valid_ip_range(const char* start, const char* end) {
    return is_valid_ip(start) && is_valid_ip(end);
}

int parse_ip_range(const char* input, IPrange *ip_range) {
    char start[MAX_IP_LENGTH], end[MAX_IP_LENGTH];
    if (sscanf(input, "%15[^-]-%15s", start, end) == 2) {
        if (is_valid_ip(start) && is_valid_ip(end)) {
            strcpy(ip_range->start, start);
            strcpy(ip_range->end, end);
            ip_range->is_range = 1; // it's a range
            return 1;
        }
    }

    if (is_valid_ip(input)) {
        strcpy(ip_range->start, input);
        ip_range->is_range = 0; // it's a single IP
        return 1;
    }
    return 0; // invalid
}
int valid_numeric_string(const char* str){
    if (*str == '-') return 0;
    while (*str)
    {
        if (!isdigit(*str) && *str != '-')
        {
            return 0;
        }
        str++;
    }
    return 1;
    
}

// Validate ports
int is_valid_port(int port) {
    return port >= 0 && port <= 65535;
}
// check if an IP address and port are allowed
void check_connection(const char* ip, int port) { // C command
    if (!is_valid_ip(ip)) {
        printf("Illegal IP address or port specified\n");
        return;
    }
    
    if (!is_valid_port(port)) {
        printf("Illegal IP address or port specified\n");
        return;
    }

    FirewallRule *current_rule = rules_head;
    while (current_rule != NULL) {
        int ip_in_range = 0;

        // Check if the IP is in the defined range
        if (current_rule->ip_range.is_range) {
            // Check if the IP falls within the range
            if (strcmp(ip, current_rule->ip_range.start) >= 0 && strcmp(ip, current_rule->ip_range.end) <= 0) {
                ip_in_range = 1;
            }
        } else {
            // Single IP check
            if (strcmp(ip, current_rule->ip_range.start) == 0) {
                ip_in_range = 1;
            }
        }

        // Check if the port is in range
        int port_in_range = (port >= current_rule->port_range.start && port <= current_rule->port_range.end);

        // bith match
        if (ip_in_range && port_in_range) {
             MatchedQuery *new_query = malloc(sizeof(MatchedQuery));
             if (new_query) {
                strcpy(new_query->ip, ip);
                new_query->port = port;
                new_query->next = current_rule->matched_queries;  
                current_rule->matched_queries = new_query;
            }
            printf("Connection accepted\n");
            return;
        }

        current_rule = current_rule->next;
    }

    // If no matches were found
    printf("Connection rejected\n"); 
}



int parse_port_range(const char *input, PortRange *port_range) {
    int start, end;
    if (!valid_numeric_string(input))
    {
        return 0;
    }
    

    if (strchr(input, '-') != NULL) {
        if (sscanf(input, "%d-%d", &start, &end) == 2) {
            if (is_valid_port(start) && is_valid_port(end) && start < end) {
                port_range->start = start;
                port_range->end = end;
                port_range->is_range = 1; // it's a range
                return 1;
            }
        }
    } else {
        if (sscanf(input, "%d", &start) == 1 && is_valid_port(start)) {
            port_range->start = start;
            port_range->end = start;
            port_range->is_range = 0;
            return 1;
        }
    }
    return 0; // Invalid port
}




char* format_rule_string(FirewallRule *rule) { //used for A command
    static char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s-%s %d-%d",
             rule->ip_range.start, rule->ip_range.is_range ? rule->ip_range.end : "",
             rule->port_range.start, rule->port_range.is_range ? rule->port_range.end : rule->port_range.start);
    return buffer;
}


void handle_add_rule(char* rule_str) { // A command
    char ip_part[MAX_RULE_LENGTH], port_part[MAX_RULE_LENGTH];
    sscanf(rule_str, "%255s %255s", ip_part, port_part);

    IPrange ip_range;
    PortRange port_range;

    

    if (parse_ip_range(ip_part, &ip_range) && parse_port_range(port_part, &port_range)) {
        FirewallRule *new_rule = malloc(sizeof(FirewallRule));
    if (new_rule) {
        new_rule->ip_range = ip_range;
        new_rule->port_range = port_range;
        new_rule->next = rules_head;
        rules_head = new_rule;
        printf("Rule added\n");
        }else {
        printf("Memory Allocation Failed.\n");
        }
    }else {
      printf("Invalid rule\n");
    } 
}



void list_requests() {
    Request *current = requests_head;
    if (current == NULL) {
        printf("No Requests\n");
        return;
    }

    // Create a temporary stack to reverse the order of printing
    Request *stack = NULL;

    // reverse
    while (current != NULL) {
        Request *new_request = malloc(sizeof(Request));
        if (new_request) {
            strcpy(new_request->command, current->command);
            new_request->next = stack;
            stack = new_request;  
        }
        current = current->next;
    }

    // Print the requests in reverse order
    printf("Requests:\n");
    while (stack != NULL) {
        printf("%s\n", stack->command);
        Request *temp = stack;
        stack = stack->next;
        free(temp);  
    }
}
void handle_delete_rule(char *rule_str) { // D command
    char ip_part[MAX_RULE_LENGTH], port_part[MAX_RULE_LENGTH];
    sscanf(rule_str, "%255s %255s", ip_part, port_part);

    IPrange ip_range;
    PortRange port_range;

    // Parse the IP and port ranges
    if (!parse_ip_range(ip_part, &ip_range) || !parse_port_range(port_part, &port_range)) {
        printf("Invalid rule\n");
        return;
    }

    FirewallRule *current = rules_head;
    FirewallRule *prev = NULL;

    // Search for the rule to delete
    while (current != NULL) {
        // Check if the current rule matches the specified IP and port ranges
        int ip_match = (current->ip_range.is_range == ip_range.is_range) &&
                       (strcmp(current->ip_range.start, ip_range.start) == 0) &&
                       (!current->ip_range.is_range || strcmp(current->ip_range.end, ip_range.end) == 0);
        int port_match = (current->port_range.start == port_range.start) &&
                         (current->port_range.is_range == port_range.is_range) &&
                         (!current->port_range.is_range || current->port_range.end == port_range.end);

        if (ip_match && port_match) {
            // Rule found; remove it from the list
            if (prev == NULL) {
                rules_head = current->next; // Deleting the head
            } else {
                prev->next = current->next; 
            }
            free(current);
            printf("Rule deleted\n");
            return;
        }
        prev = current;
        current = current->next;
    }

    printf("Rule not found: %s %s\n", ip_part, port_part);
}

void list_all_rules_and_queries() { // L command
    FirewallRule *current_rule = rules_head;

    if (current_rule == NULL) {
        // Don't print anything for the L command if no rules
    } else {
        
    while (current_rule != NULL) {
            // Print the rule in the specified format
        printf("Rule: %s-%s %d-%d\n",
                current_rule->ip_range.start,
                current_rule->ip_range.is_range ? current_rule->ip_range.end : "",
                current_rule->port_range.start,
                current_rule->port_range.is_range ? current_rule->port_range.end : current_rule->port_range.start);

            // Print matched queries for the current rule if found
            MatchedQuery *current_query = current_rule->matched_queries;
            while (current_query != NULL) {
                printf("Query: %s %d\n", current_query->ip, current_query->port);
                current_query = current_query->next;
            }

            // Move to the next rule
            current_rule = current_rule->next;
        }
    }
}


void cleanup(){
    FirewallRule *current = rules_head;
    while(current != NULL){
        FirewallRule *temp = current;
        current = current->next;
        free(temp);

    }
}
void *processRequest(void *args) {
    int *newsockfd = (int *)args;
    int n;
    char *buffer = readRes(*newsockfd);
    char responseBuffer[BUFFERLENGTH];

    if (!buffer) {
        // send error response to client directly
        snprintf(responseBuffer, sizeof(responseBuffer), "ERROR: Failed to read request from client.\n");
        writeResult(*newsockfd, responseBuffer, strlen(responseBuffer) + 1);
        close(*newsockfd);
        free(newsockfd);
        pthread_exit(NULL);
    }

    // Lock mutex for exclusive access
    pthread_mutex_lock(&mut);
    char commandType = buffer[0];
    char *commandArgument = buffer + 2;

    
    if (strncmp(buffer, "A ", 2) == 0) {  // Add rule
        handle_add_rule(commandArgument);
        store_request(buffer);  // Store the 'A' command
        snprintf(responseBuffer, sizeof(responseBuffer), "Rule added\n");

    } else if (strcmp(buffer, "R") == 0) {  // List requests
        list_requests();
        store_request(buffer);  // Store the 'R' command
        snprintf(responseBuffer, sizeof(responseBuffer), "Requests:\n");

    } else if (strncmp(buffer, "C ", 2) == 0) {  // Check connection
        char ip[MAX_IP_LENGTH];
        int port;
        if (sscanf(commandArgument, "%15s %d", ip, &port) == 2) {
            check_connection(ip, port);
            snprintf(responseBuffer, sizeof(responseBuffer), "Connection accepted\n"); 
        } else {
            snprintf(responseBuffer, sizeof(responseBuffer), "Connection rejected\n"); 
        }
        store_request(buffer);  // Store the 'C' command

    } else if (strncmp(buffer, "D ", 2) == 0) {  // Delete rule
        handle_delete_rule(commandArgument);
        store_request(buffer);  // Store the 'D' command
        snprintf(responseBuffer, sizeof(responseBuffer), "Rule deleted\n");

    } else if (strcmp(buffer, "L") == 0) {  // List all rules and queries
        list_all_rules_and_queries();
        store_request(buffer);  // Store the 'L' command
        snprintf(responseBuffer, sizeof(responseBuffer), "Rules and requests\n");

    } else {
        snprintf(responseBuffer, sizeof(responseBuffer), "Illegal Request '%c'.\n", commandType);
    }

    // Increment execution count and unlock mutex
    isExecuted++;
    pthread_mutex_unlock(&mut);

    
    n = writeResult(*newsockfd, responseBuffer, strlen(responseBuffer) + 1);
    if (n < 0) {
        
        fprintf(stderr, "ERROR writing to socket\n");
    }

    // Clean up
    free(buffer);
    close(*newsockfd);
    free(newsockfd);

    pthread_exit(NULL);
}



int writeResult (int sockfd, char *buffer, size_t bufsize) {
    int n;
   
    n = write(sockfd, &bufsize, sizeof(size_t));
    if (n < 0) {
		fprintf (stderr, "ERROR writing to result\n");
		return -1;
    }
    
    n = write(sockfd, buffer, bufsize);
    if (n != bufsize) {
		fprintf (stderr, "Couldn't write %ld bytes, wrote %d bytes\n", bufsize, n);
		return -1;
    }
    return 0;
}

char *readRes(int sockfd) {
    size_t bufsize;
    int res;
    char *buffer;

    res = read(sockfd, &bufsize, sizeof(size_t));
    if (res != sizeof(size_t)) {
		fprintf (stderr, "Reading number of bytes from socket failed\n");
		return NULL;
    }

    buffer = malloc(bufsize+1);
    if (buffer) {
		buffer[bufsize]  = '\0';
		res = read(sockfd, buffer, bufsize);
		if (res != bufsize) {
			fprintf (stderr, "Reading reply from socket\n");
			free(buffer);
			return NULL;
		}
    }
    
    return buffer;
}  
void store_request(const char *command) {
    
    Request *new_request = malloc(sizeof(Request));
    if (new_request) {
        strcpy(new_request->command, command);  // Store the entire command
        new_request->next = requests_head;
        requests_head = new_request;  // Add it to the request list
    }
}


int main(int argc, char **argv) {
    int sockfd;  
    struct sockaddr_in6 serv_addr;

    // valid command line arguements only
     if (argc != 2 || (strcmp(argv[1], "-i") != 0 && !isdigit(argv[1][0]))) {
        fprintf(stderr, "Invalid command. Usage: %s -i or %s [port number]\n", argv[0], argv[0]);
        return 1; 
        }

    // Interactive mode
    if (argc > 1 && strcmp(argv[1], "-i") == 0) {
        char command[MAX_RULE_LENGTH]; 
        
        while (1) {
            if (fgets(command, sizeof(command), stdin) == NULL) {
                break;
            }
            command[strcspn(command, "\n")] = 0; // Remove newline

        if (strncmp(command, "A ", 2) == 0) {  // Add rule
           handle_add_rule(command + 2);
           store_request(command);  // Store the 'A' command

       }else if (strcmp(command, "R") == 0) {  // List requests
            store_request(command);  // Store the 'R' command only once
            list_requests();  // List requests
       }else if (strncmp(command, "C ", 2) == 0) {  // Check connection
           char ip[MAX_IP_LENGTH];
           int port;
        if (sscanf(command + 2, "%15s %d", ip, &port) == 2) {
         check_connection(ip, port);
       } else {
        printf("Illegal IP address or port specified.\n");
    }
    store_request(command);  // Store the 'C' command

} else if (strncmp(command, "D ", 2) == 0) {  // Delete rule
    handle_delete_rule(command + 2);
    store_request(command);  // Store the 'D' command

} else if (strcmp(command, "L") == 0) {  // List all rules and queries
    list_all_rules_and_queries();
    store_request(command);  // Store the 'L' command
} else {
    printf("Illegal Request\n");
}
        }
      
        cleanup();
    }
    // Port mode
    else if (argc == 2) {
        int portno = atoi(argv[1]);

        // Create socket
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Error opening socket");
            return 1;
        }

        memset((char *)&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin6_family = AF_INET6;
        serv_addr.sin6_addr = in6addr_any;
        serv_addr.sin6_port = htons(portno);

        // Bind the socket
        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Error on binding");
            return 1;
        }

        listen(sockfd, 5);
      

        // Wait for connections and process them
        while (1) {
            pthread_t server_thread;
            int *newsockfd;
            struct sockaddr_in6 cli_addr;
            socklen_t clilen = sizeof(cli_addr);

            newsockfd = malloc(sizeof(int));
            if (!newsockfd) {
                fprintf(stderr, "Memory allocation failed!\n");
                continue;
            }

            *newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (*newsockfd < 0) {
                perror("Error on accept");
                free(newsockfd);
                continue;
            }

            // Create a new thread to handle the request
            int result = pthread_create(&server_thread, NULL, processRequest, (void *)newsockfd);
            if (result != 0) {
                fprintf(stderr, "Thread creation failed!\n");
                free(newsockfd);
            }
        }
    } else {
        printf("Usage: %s <port>\n", argv[0]);
    }

    return 0;
}
          