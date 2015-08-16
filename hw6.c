/*
 * hw6.c
 *
 *  Created on: Apr 11, 2015
 *      Author: prabhaks
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "hw6.h"

static char *option;
// program name
static char gszProgName[MAXPATHLENGTH];
static char key[KEYLEN + 1];
static char p1[POLYLEN + 1], p2[POLYLEN + 1];
static FILE *tf = NULL, *fp = NULL;

static
void Usage(char *message) {
	fprintf(stderr, "Command %s %s\n", gszProgName, message);
	exit(-1);
}

static void Error(char *message, char *field) {
	fprintf(stderr, "Error: %s %s\n", message, field);
	Usage(
			" Usage: Please specify command with valid argument(s). For example, 'tablecheck -t=tablefile', 'modprod -p1=poly1 -p2=poly2', 'keyexpand -k=key -t=tablefile', 'encrypt -k=key -t=tablefile [file]', 'decrypt -k=key -t=tablefile [file]', 'inverse -p=poly'. To read input data, file (if specified) or standard input is used.");
}

static void ProcessInputAndOutput() {
	// option check for input tables checker
	if (strcmp(option, "tablecheck") == 0) {
		ProcessTableCheck(tf);
	}
	// option check for performing modulus product of two polynomials
	else if (strcmp(option, "modprod") == 0) {
		ProcessModProd(p1, p2);
	}
	// option check for performing key expansion operation
	else if (strcmp(option, "keyexpand") == 0) {
		ProcessKeyExpand(key, tf);
	}
	// option check for performing encrypt operation
	else if (strcmp(option, "encrypt") == 0) {
		ProcessEncrypt(key, tf, fp);
	}
	// option check for performing decrypt operation
	else if (strcmp(option, "decrypt") == 0) {
		ProcessDecrypt(key, tf, fp);
		// calculate inverse using table method
	} else {
		ProcessInverse(p1);
	}
}

/**
 * sets program name as hw6
 */
static void SetProgramName(char *s) {
// remove / from command name
	char *c_ptr = strrchr(s, DIR_SEP);

	if (c_ptr == NULL) {
		strcpy(gszProgName, s);
	} else {
		strcpy(gszProgName, ++c_ptr);
	}
}

/**
 * It sets fileName global variable to point to input file.
 * Error checking is performed for malformed inputs
 */
static void ProcessOptions(int argc, char *argv[]) {
	if (argc < 2)
		Error("can not run without any argument.", "");
	option = *++argv;
	char *key_ptr, *value_ptr;
	// parse command line for several supported options
	if (strcmp(option, "tablecheck") == 0) {
		if (argc != 3) {
			Usage(
					"should be run with proper options. Use 'tablecheck -t=tablefile' in this exact format. tablefile is input table filename.");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			value_ptr = strchr(*argv, '=');
			// option must exist in format -p=pass
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'tablecheck -t=tablefile' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'tablecheck -t=tablefile'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-t") == 0) {
				tf = fopen(value_ptr, "r");
				if (tf == NULL) {
					// throw error in case of file pointer resulting NULL
					fprintf(stderr,
							"Error :  Could not open file '%s' for read operation. %s\n",
							value_ptr, strerror(errno));
					exit(1);
				}
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for tablecheck operation. Usage : 'tablecheck -t=tablefile'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
	} else if (strcmp(option, "modprod") == 0) {
		if (argc != 4) {
			Usage(
					"should be run with proper options. Use 'modprod -p1=poly1 -p2=poly2' in this exact format. poly1 and poly2 are two 4 byte polynomials input in hex string");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			value_ptr = strchr(*argv, '=');
			// option must exist in format -p=pass
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'modprod -p1=poly1 -p2=poly2' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'modprod -p1=poly1 -p2=poly2'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-p1") == 0) {
				strncpy(p1, value_ptr, POLYLEN);
			} else if (strcmp(key_ptr, "-p2") == 0) {
				strncpy(p2, value_ptr, POLYLEN);
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for modprod operation. Usage : 'modprod -p1=poly1 -p2=poly2'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			// option must exist in format -t=period
			value_ptr = strchr(*argv, '=');
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'modprod -p1=poly1 -p2=poly2' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'modprod -p1=poly1 -p2=poly2'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-p1") == 0) {
				strncpy(p1, value_ptr, POLYLEN);
			} else if (strcmp(key_ptr, "-p2") == 0) {
				strncpy(p2, value_ptr, POLYLEN);
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for modprod operation. Usage : 'modprod -p1=poly1 -p2=poly2'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}

	} else if (strcmp(option, "keyexpand") == 0) {
		if (argc != 4) {
			Usage(
					"should be run with proper options. Use 'keyexpand -k=key -t=tablefile' in this exact format. key is input key to be expanded using table file");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			value_ptr = strchr(*argv, '=');
			// option must exist in format -p=pass
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'keyexpand -k=key -t=tablefile' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'keyexpand -k=key -t=tablefile'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-k") == 0) {
				strncpy(key, value_ptr, KEYLEN);
			} else if (strcmp(key_ptr, "-t") == 0) {
				// open file in read mode
				tf = fopen(value_ptr, "r");
				if (tf == NULL) {
					// throw error in case of file pointer resulting NULL
					fprintf(stderr,
							"Error :  Could not open file '%s' for read operation. %s\n",
							value_ptr, strerror(errno));
					exit(1);
				}
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for keyexpand operation. Usage : 'keyexpand -k=key -t=tablefile'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			// option must exist in format -t=period
			value_ptr = strchr(*argv, '=');
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'keyexpand -k=key -t=tablefile' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'keyexpand -k=key -t=tablefile'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-k") == 0) {
				strncpy(key, value_ptr, KEYLEN);
			} else if (strcmp(key_ptr, "-t") == 0) {
				// open file in read mode
				tf = fopen(value_ptr, "r");
				if (tf == NULL) {
					// throw error in case of file pointer resulting NULL
					fprintf(stderr,
							"Error :  Could not open file '%s' for read operation. %s\n",
							value_ptr, strerror(errno));
					exit(1);
				}
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for keyexpand operation. Usage : 'keyexpand -k=key -t=tablefile'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
	} else if (strcmp(option, "encrypt") == 0) {
		if (argc < 4) {
			Usage(
					"should be run with proper options. Use 'encrypt -k=key -t=tablefile [file]' in this exact format. If file if specified, input is read from it else standard input is used. key is hex string of length 32");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			value_ptr = strchr(*argv, '=');
			// option must exist in format -p=pass
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'encrypt -k=key -t=tablefile [file]' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'encrypt -k=key -t=tablefile [file]'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-k") == 0) {
				strncpy(key, value_ptr, KEYLEN);
			} else if (strcmp(key_ptr, "-t") == 0) {
				// open file in read mode
				tf = fopen(value_ptr, "r");
				if (tf == NULL) {
					// throw error in case of file pointer resulting NULL
					fprintf(stderr,
							"Error :  Could not open file '%s' for read operation. %s\n",
							value_ptr, strerror(errno));
					exit(1);
				}
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for encrypt operation. Usage : 'encrypt -k=key -t=tablefile [file]'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			// option must exist in format -t=period
			value_ptr = strchr(*argv, '=');
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'encrypt -k=key -t=tablefile [file]' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'encrypt -k=key -t=tablefile [file]'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-k") == 0) {
				strncpy(key, value_ptr, KEYLEN);
			} else if (strcmp(key_ptr, "-t") == 0) {
				// open file in read mode
				tf = fopen(value_ptr, "r");
				if (tf == NULL) {
					// throw error in case of file pointer resulting NULL
					fprintf(stderr,
							"Error :  Could not open file '%s' for read operation. %s\n",
							value_ptr, strerror(errno));
					exit(1);
				}
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for encrypt operation. Usage : 'encrypt -k=key -t=tablefile [file]'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
		if (argc > 4) {
			// open file in read mode
			fp = fopen(*++argv, "r");
			if (fp == NULL) {
				// throw error in case of file pointer resulting NULL
				fprintf(stderr,
						"Error :  Could not open file '%s' for read operation. %s\n",
						*argv, strerror(errno));
				exit(1);
			}
		} else
			// use sdtin if file is not specified
			fp = stdin;

	} else if (strcmp(option, "decrypt") == 0) {
		if (argc < 4) {
			Usage(
					"should be run with proper options. Use 'decrypt -k=key -t=tablefile [file]' in this exact format. If file if specified, input is read from it else standard input is used. key is hex string of length 32");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			value_ptr = strchr(*argv, '=');
			// option must exist in format -p=pass
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'decrypt -k=key -t=tablefile [file]' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'decrypt -k=key -t=tablefile [file]'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-k") == 0) {
				strncpy(key, value_ptr, KEYLEN);
			} else if (strcmp(key_ptr, "-t") == 0) {
				// open file in read mode
				tf = fopen(value_ptr, "r");
				if (tf == NULL) {
					// throw error in case of file pointer resulting NULL
					fprintf(stderr,
							"Error :  Could not open file '%s' for read operation. %s\n",
							value_ptr, strerror(errno));
					exit(1);
				}
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for decrypt operation. Usage : 'decrypt -k=key -t=tablefile [file]'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			// option must exist in format -t=period
			value_ptr = strchr(*argv, '=');
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'decrypt -k=key -t=tablefile [file]' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'decrypt -k=key -t=tablefile [file]'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-k") == 0) {
				strncpy(key, value_ptr, KEYLEN);
			} else if (strcmp(key_ptr, "-t") == 0) {
				// open file in read mode
				tf = fopen(value_ptr, "r");
				if (tf == NULL) {
					// throw error in case of file pointer resulting NULL
					fprintf(stderr,
							"Error :  Could not open file '%s' for read operation. %s\n",
							value_ptr, strerror(errno));
					exit(1);
				}
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for decrypt operation. Usage : 'decrypt -k=key -t=tablefile [file]'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
		if (argc > 4) {
			// open file in read mode
			fp = fopen(*++argv, "r");
			if (fp == NULL) {
				// throw error in case of file pointer resulting NULL
				fprintf(stderr,
						"Error :  Could not open file '%s' for read operation. %s\n",
						*argv, strerror(errno));
				exit(1);
			}
		} else
			// use sdtin if file is not specified
			fp = stdin;

	} else if (strcmp(option, "inverse") == 0) {
		if (argc != 3) {
			Usage(
					"should be run with proper options. Use 'inverse -p=poly' in this exact format. poly is 4 byte polynomial in hex string representation.");
		}
		argv++;
		// option has to start with '-'
		if (*argv[0] == '-') {
			key_ptr = *argv;
			value_ptr = strchr(*argv, '=');
			// option must exist in format -p=pass
			if (value_ptr == NULL) {
				Usage(
						"should be run with proper options format. Missing '='. Use 'inverse -p=poly' in this exact format.");
			}
			*value_ptr = '\0';
			value_ptr++;
			if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
				fprintf(stderr,
						"Error :  command option(s) value can not be left blank. Usage : 'inverse -p=poly'\n");
				exit(1);
			}
			if (strcmp(key_ptr, "-p") == 0) {
				strncpy(p1, value_ptr, POLYLEN);
			} else {
				fprintf(stderr,
						"Error :  Improper option name '%s' for inverse operation. Usage : 'inverse -p=poly'\n",
						key_ptr);
				exit(1);
			}
		} else {
			Error("option should start with", "-");
		}
	} else {
		Error("Invalid argument for", option);
	}
}

/* ----------------------- main program ----------------------- */

int main(int argc, char *argv[]) {
// set program name
	SetProgramName(*argv);
// process options
	ProcessOptions(argc, argv);
// process input and output result
	ProcessInputAndOutput();
// finally close the file pointer
	if (fp != NULL && fp != stdin)
		fclose(fp);
	if (tf != NULL)
		fclose(tf);
	return (0);
}
