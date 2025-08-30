/* cli.h */
#ifndef CLI_H
#define CLI_H

#ifdef __cplusplus
extern "C" {
#endif

void cli_usage(const char *prog);
void cli_parse(int argc, char **argv);  // ignores unknown args

#ifdef __cplusplus
}
#endif
#endif /* CLI_H */
