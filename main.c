#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include "mujs.h"
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
//
// BEGIN FUZZING CODE
//
#ifdef  __linux__
#define S_IREAD __S_IREAD
#define S_IWRITE __S_IWRITE
#endif
#define REPRL_CRFD 100
#define REPRL_CWFD 101
#define REPRL_DRFD 102
#define REPRL_DWFD 103

#define SHM_SIZE 0x100000
#define MAX_EDGES ((SHM_SIZE - 4) * 8)

#define CHECK(cond) if (!(cond)) { fprintf(stderr, "\"" #cond "\" failed\n"); _exit(-1); }

struct shmem_data {
    uint32_t num_edges;
    unsigned char edges[];
};

struct shmem_data* __shmem;
uint32_t *__edges_start, *__edges_stop;

void __sanitizer_cov_reset_edgeguards() {
    uint64_t N = 0;
    for (uint32_t *x = __edges_start; x < __edges_stop && N < MAX_EDGES; x++)
        *x = ++N;
}

 void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    // Avoid duplicate initialization
    if (start == stop || *start)
        return;

    if (__edges_start != NULL || __edges_stop != NULL) {
        fprintf(stderr, "Coverage instrumentation is only supported for a single module\n");
        _exit(-1);
    }

    __edges_start = start;
    __edges_stop = stop;

    // Map the shared memory region
    const char* shm_key = getenv("SHM_ID");
    if (!shm_key) {
        puts("[COV] no shared memory bitmap available, skipping");
        __shmem = (struct shmem_data*) malloc(SHM_SIZE);
    } else {
        int fd = shm_open(shm_key, O_RDWR, S_IREAD | S_IWRITE);
        if (fd <= -1) {
            fprintf(stderr, "Failed to open shared memory region: %s\n", strerror(errno));
            _exit(-1);
        }

        __shmem = (struct shmem_data*) mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (__shmem == MAP_FAILED) {
            fprintf(stderr, "Failed to mmap shared memory region\n");
            _exit(-1);
        }
    }

    __sanitizer_cov_reset_edgeguards();

    __shmem->num_edges = stop - start;
    printf("[COV] edge counters initialized. Shared memory: %s with %u edges\n", shm_key, __shmem->num_edges);
}
 void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    // There's a small race condition here: if this function executes in two threads for the same
    // edge at the same time, the first thread might disable the edge (by setting the guard to zero)
    // before the second thread fetches the guard value (and thus the index). However, our
    // instrumentation ignores the first edge (see libcoverage.c) and so the race is unproblematic.
    uint32_t index = *guard;
    // If this function is called before coverage instrumentation is properly initialized we want to return early.
    if (!index) return;
    __shmem->edges[index / 8] |= 1 << (index % 8);
    *guard = 0;
}

//
// END FUZZING CODE
//
static char *xoptarg; /* Global argument pointer. */
static int xoptind = 0; /* Global argv index. */
static int xgetopt(int argc, char *argv[], char *optstring)
{
	static char *scan = NULL; /* Private scan pointer. */

	char c;
	char *place;

	xoptarg = NULL;

	if (!scan || *scan == '\0') {
		if (xoptind == 0)
			xoptind++;

		if (xoptind >= argc || argv[xoptind][0] != '-' || argv[xoptind][1] == '\0')
			return EOF;
		if (argv[xoptind][1] == '-' && argv[xoptind][2] == '\0') {
			xoptind++;
			return EOF;
		}

		scan = argv[xoptind]+1;
		xoptind++;
	}

	c = *scan++;
	place = strchr(optstring, c);

	if (!place || c == ':') {
		fprintf(stderr, "%s: unknown option -%c\n", argv[0], c);
		return '?';
	}

	place++;
	if (*place == ':') {
		if (*scan != '\0') {
			xoptarg = scan;
			scan = NULL;
		} else if (xoptind < argc) {
			xoptarg = argv[xoptind];
			xoptind++;
		} else {
			fprintf(stderr, "%s: option requires argument -%c\n", argv[0], c);
			return ':';
		}
	}

	return c;
}

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#else
void using_history(void) { }
void add_history(const char *string) { }
void rl_bind_key(int key, void (*fun)(void)) { }
void rl_insert(void) { }
char *readline(const char *prompt)
{
	static char line[500], *p;
	int n;
	fputs(prompt, stdout);
	p = fgets(line, sizeof line, stdin);
	if (p) {
		n = strlen(line);
		if (n > 0 && line[n-1] == '\n')
			line[--n] = 0;
		p = malloc(n+1);
		memcpy(p, line, n+1);
		return p;
	}
	return NULL;
}
#endif

#define PS1 "> "

static void jsB_gc(js_State *J)
{
	int report = js_toboolean(J, 1);
	js_gc(J, report);
	js_pushundefined(J);
}

static void jsB_load(js_State *J)
{
	int i, n = js_gettop(J);
	for (i = 1; i < n; ++i) {
		js_loadfile(J, js_tostring(J, i));
		js_pushundefined(J);
		js_call(J, 0);
		js_pop(J, 1);
	}
	js_pushundefined(J);
}

static void jsB_compile(js_State *J)
{
	const char *source = js_tostring(J, 1);
	const char *filename = js_isdefined(J, 2) ? js_tostring(J, 2) : "[string]";
	js_loadstring(J, filename, source);
}

static void jsB_print(js_State *J)
{
	int i, top = js_gettop(J);
	for (i = 1; i < top; ++i) {
		const char *s = js_tostring(J, i);
		if (i > 1) putchar(' ');
		fputs(s, stdout);
	}
	putchar('\n');
	js_pushundefined(J);
}

static void jsB_write(js_State *J)
{
	int i, top = js_gettop(J);
	for (i = 1; i < top; ++i) {
		const char *s = js_tostring(J, i);
		if (i > 1) putchar(' ');
		fputs(s, stdout);
	}
	js_pushundefined(J);
}

static void jsB_read(js_State *J)
{
	const char *filename = js_tostring(J, 1);
	FILE *f;
	char *s;
	int n, t;

	f = fopen(filename, "rb");
	if (!f) {
		js_error(J, "cannot open file '%s': %s", filename, strerror(errno));
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		fclose(f);
		js_error(J, "cannot seek in file '%s': %s", filename, strerror(errno));
	}

	n = ftell(f);
	if (n < 0) {
		fclose(f);
		js_error(J, "cannot tell in file '%s': %s", filename, strerror(errno));
	}

	if (fseek(f, 0, SEEK_SET) < 0) {
		fclose(f);
		js_error(J, "cannot seek in file '%s': %s", filename, strerror(errno));
	}

	s = malloc(n + 1);
	if (!s) {
		fclose(f);
		js_error(J, "out of memory");
	}

	t = fread(s, 1, n, f);
	if (t != n) {
		free(s);
		fclose(f);
		js_error(J, "cannot read data from file '%s': %s", filename, strerror(errno));
	}
	s[n] = 0;

	js_pushstring(J, s);
	free(s);
	fclose(f);
}

static void jsB_readline(js_State *J)
{
	char *line = readline("");
	if (!line) {
		js_pushnull(J);
		return;
	}
	js_pushstring(J, line);
	if (*line)
		add_history(line);
	free(line);
}

static void jsB_quit(js_State *J)
{
	exit(js_tonumber(J, 1));
}

static void jsB_repr(js_State *J)
{
	js_repr(J, 1);
}

static const char *require_js =
	"function require(name) {\n"
	"var cache = require.cache;\n"
	"if (name in cache) return cache[name];\n"
	"var exports = {};\n"
	"cache[name] = exports;\n"
	"Function('exports', read(name+'.js'))(exports);\n"
	"return exports;\n"
	"}\n"
	"require.cache = Object.create(null);\n"
;

static const char *stacktrace_js =
	"Error.prototype.toString = function() {\n"
	"if (this.stackTrace) return this.name + ': ' + this.message + this.stackTrace;\n"
	"return this.name + ': ' + this.message;\n"
	"};\n"
;

static int eval_print(js_State *J, const char *source)
{
	if (js_ploadstring(J, "[stdin]", source)) {
		fprintf(stderr, "%s\n", js_trystring(J, -1, "Error"));
		js_pop(J, 1);
		return 1;
	}
	js_pushundefined(J);
	if (js_pcall(J, 0)) {
		fprintf(stderr, "%s\n", js_trystring(J, -1, "Error"));
		js_pop(J, 1);
		return 1;
	}
	if (js_isdefined(J, -1)) {
		printf("%s\n", js_tryrepr(J, -1, "can't convert to string"));
	}
	js_pop(J, 1);
	return 0;
}

static char *read_stdin(void)
{
	int n = 0;
	int t = 512;
	char *s = NULL;

	for (;;) {
		char *ss = realloc(s, t);
		if (!ss) {
			free(s);
			fprintf(stderr, "cannot allocate storage for stdin contents\n");
			return NULL;
		}
		s = ss;
		n += fread(s + n, 1, t - n - 1, stdin);
		if (n < t - 1)
			break;
		t *= 2;
	}

	if (ferror(stdin)) {
		free(s);
		fprintf(stderr, "error reading stdin\n");
		return NULL;
	}

	s[n] = 0;
	return s;
}
void fuzzilli(js_State *J) {
  // pop arg of the stack
  const char* str = js_tostring(J, 1);
  if (!str) {
    printf("js_fuzzilli NO CMD\n");
    return;
  }
  if (!strcmp(str, "FUZZILLI_CRASH")) {
		printf("js_fuzzilli CRASH\n");
//     // switch (type) {
//     //   case 0:
         *((int*)0x41414141) = 0x1337;
//     //     break;
//     //   case 1:
//     //     assert(0);
//     //     break;
//     //   default:
//     //     assert(0);
//     //     break;
	} else if (!strcmp(str, "FUZZILLI_PRINT")) {
			// get next argument off the stack to print
			const char* print_str = js_tostring(J, 2);
			printf("js_fuzzilli PRINT %s\n", print_str);
			FILE* fzliout = fdopen(REPRL_DWFD, "w");
			if (!fzliout) {
				fprintf(stderr, "Fuzzer output channel not available, printing to stdout instead\n");
				fzliout = stdout;
			}
			if (print_str) {
				fprintf(fzliout, "%s\n", print_str);
			}
			fflush(fzliout);
	}
  return;
}

static void usage(void)
{
	fprintf(stderr, "Usage: mujs [options] [script [scriptArgs*]]\n");
	fprintf(stderr, "\t-i: Enter interactive prompt after running code.\n");
	fprintf(stderr, "\t-s: Check strictness.\n");
	fprintf(stderr, "\t-f: Fuzzilli mode.\n");
	exit(1);
}

int main(int argc, char **argv){
	// char *input;
	js_State *J;
	int status = 0;
	int strict = 0;
	// int interactive = 0;
	// int c;
	// Let parent know we are ready
	// write "HELO" on REPRL_CWFD
	if(argc>=2){
		char helo[] = "HELO";
		// read 4 bytes on REPRL_CRFD
		if( (write(REPRL_CWFD, helo, 4) != 4) || (read(REPRL_CRFD, helo, 4) != 4)) {
			fprintf(stderr, "Error writing or reading HELO\n");
			_exit(-1);
		} else {
			// break if 4 read bytes do not equal "HELO"
			if (memcmp(helo, "HELO", 4) != 0) {
			fprintf(stderr, "Invalid response from parent\n");
				_exit(-1);
			}
			// while true
			while(1){
				// read 4 bytes on REPRL_CRFD
				unsigned action = 0;
				ssize_t nread = read(REPRL_CRFD, &action, 4);
				fflush(0);
				// break if 4 read bytes do not equal "cexe"
				if (nread != 4 || action != 0x63657865) { // 'exec'
					fprintf(stderr, "Unknown action: %x\n", action);
					_exit(-1);
				}
				// read 8 bytes on REPRL_CRFD, store as unsigned 64 bit integer size
				size_t script_size = 0;
				read(REPRL_CRFD, &script_size, 8);
				ssize_t remaining = (ssize_t) script_size;
				// allocate size+1 bytes
				char* buffer = (char*)malloc(script_size+1);
				// read size bytes from REPRL_DRFD into allocated buffer,
				ssize_t rv = read(REPRL_DRFD, buffer, (size_t) remaining);
				if (rv <= 0) {
					fprintf(stderr, "Failed to load script\n");
					_exit(-1);
				}
				buffer[script_size] = 0;
				// Execute buffer as javascript code
				J = js_newstate(NULL, NULL, strict ? JS_STRICT : 0);
				js_newcfunction(J, jsB_gc, "gc", 0);
				js_setglobal(J, "gc");
				js_newcfunction(J, jsB_load, "load", 1);
				js_setglobal(J, "load");
				js_newcfunction(J, jsB_compile, "compile", 2);
				js_setglobal(J, "compile");
				js_newcfunction(J, jsB_print, "print", 0);
				js_setglobal(J, "print");
				js_newcfunction(J, jsB_write, "write", 0);
				js_setglobal(J, "write");
				js_newcfunction(J, jsB_read, "read", 1);
				js_setglobal(J, "read");
				js_newcfunction(J, jsB_readline, "readline", 0);
				js_setglobal(J, "readline");
				js_newcfunction(J, jsB_repr, "repr", 0);
				js_setglobal(J, "repr");
				js_newcfunction(J, jsB_quit, "quit", 1);
				js_setglobal(J, "quit");
				js_newcfunction(J, fuzzilli, "fuzzilli", 2);
				js_setglobal(J, "fuzzilli");
				js_dostring(J, require_js);
				js_dostring(J, stacktrace_js);
				// Store return value from JS execution
				int ret_value = js_dostring(J, buffer);
				if(ret_value != 0) {  fprintf(stderr, "Failed to eval_buf reprl\n"); }
				// Flush stdout and stderr. As REPRL sets them to regular files, libc uses full bufferring for them, which means they need to be flushed after every execution
				fflush(stdout);
				fflush(stderr);
				// Mask return value with 0xff and shift it left by 8, then write that value over REPRL_CWFD
				// Send return code to parent and reset edge counters.
				status = (ret_value & 0xff) << 8;
				if(write(REPRL_CWFD, &status, 4) != 4){ fprintf(stderr, "Erroring writing return value over REPRL_CWFD\n"); }
				__sanitizer_cov_reset_edgeguards();
				// Reset the Javascript engine
				// Call __sanitizer_cov_reset_edgeguards to reset coverage
				// TODO: later fuzz strict mode as well
			}
		}
	}else{
				char* buffer = (char*)malloc(150);
				read(0, buffer, 149);
				J = js_newstate(NULL, NULL, strict ? JS_STRICT : 0);
				js_newcfunction(J, jsB_gc, "gc", 0);
				js_setglobal(J, "gc");
				js_newcfunction(J, jsB_load, "load", 1);
				js_setglobal(J, "load");
				js_newcfunction(J, jsB_compile, "compile", 2);
				js_setglobal(J, "compile");
				js_newcfunction(J, jsB_print, "print", 0);
				js_setglobal(J, "print");
				js_newcfunction(J, jsB_write, "write", 0);
				js_setglobal(J, "write");
				js_newcfunction(J, jsB_read, "read", 1);
				js_setglobal(J, "read");
				js_newcfunction(J, jsB_readline, "readline", 0);
				js_setglobal(J, "readline");
				js_newcfunction(J, jsB_repr, "repr", 0);
				js_setglobal(J, "repr");
				js_newcfunction(J, jsB_quit, "quit", 1);
				js_setglobal(J, "quit");
				js_newcfunction(J, fuzzilli, "fuzzilli", 1);
				js_setglobal(J, "fuzzilli");
				js_dostring(J, require_js);
				js_dostring(J, stacktrace_js);
				js_dostring(J, buffer);
	}
		return 0;
}
