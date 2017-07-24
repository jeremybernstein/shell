/*
shell Copyright © 2013 Jeremy Bernstein and Bill Orcutt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "ext.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MESSAGELEN	4096

#ifdef MAC_VERSION
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/termios.h>
#include <pthread.h>
#else
#ifndef Boolean
#define Boolean bool
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#ifdef MAC_VERSION
typedef int t_fildes;
typedef int t_procid;
#define t_fildes	int
#define WRITE(f,s)	write(f, s, strlen(s))
#define READ		read
#define READ_HANDLE(x)	x->fd
#define WRITE_HANDLE(x) x->fd
#else
typedef HANDLE t_fildes;
typedef HANDLE t_procid;
#define WRITE			WriteToPipe
#define READ			ReadFromPipe
#define READ_HANDLE(e)	x->fd_r
#define WRITE_HANDLE(e) x->fd_w
#define CLEAN_CLOSEHANDLE(h) if (h) { CloseHandle(h); h = 0; }
#define kill windows_kill

extern BOOL
APIENTRY
MyCreatePipeEx(
			   OUT LPHANDLE lpReadPipe,
			   OUT LPHANDLE lpWritePipe,
			   IN LPSECURITY_ATTRIBUTES lpPipeAttributes,
			   IN DWORD nSize,
			   DWORD dwReadMode,
			   DWORD dwWriteMode,
			   DWORD dwPipeMode
			   );
int WriteToPipe(HANDLE fh, char *str);
int ReadFromPipe(HANDLE fh, char *str, DWORD slen);
#endif

typedef struct _shell
{
    t_object		ob;
	void			*pollqfn;	//shutdown
	void			*textout;
	void			*bangout;
	char			cmdbuf[MAX_MESSAGELEN]; //command
#ifdef MAC_VERSION
	t_fildes		fd;
#else
	t_fildes		fd_r;
	t_fildes		fd_w;
#endif
	t_procid		pid;
	char			merge_stderr;
	t_symbol		*wd;
	t_symbol		*shell;
#ifdef WIN_VERSION
	char			unicode;
#endif
} t_shell;

t_class *shell_class;

void doReport();
void shell_bang(t_shell *x);
void shell_anything(t_shell *x, t_symbol *s, long ac, t_atom *av);
void shell_do(t_shell *x, t_symbol *s, long ac, t_atom *av);
void shell_write(t_shell *x, t_symbol *s, long ac, t_atom *av);
void shell_dowrite(t_shell *x, t_symbol *s, long ac, t_atom *av);
void shell_stop(t_shell *x);	
void shell_kill(t_shell *x);
void shell_qfn(t_shell *x);
void shell_assist(t_shell *x, void *b, long m, long a, char *s);
void shell_free(t_shell *x);
void *shell_new(t_symbol *s, long ac, t_atom *av);
void shell_output(t_shell *x, t_symbol *s, long ac, t_atom *av);
Boolean shell_readline(t_shell *x);
void shell_atoms2text(long ac, t_atom *av, char *text);

t_max_err shell_attr_wd_set(t_shell *x, void *attr, long ac, t_atom *av);
t_max_err shell_attr_wd_get(t_shell *x, void *attr, long *ac, t_atom **av);
t_max_err shell_attr_shell_set(t_shell *x, void *attr, long ac, t_atom *av);
t_max_err shell_attr_shell_get(t_shell *x, void *attr, long *ac, t_atom **av);

int shell_pipe_open(t_shell *x, t_fildes *masterfd_r, t_fildes *masterfd_w, char *cmd, char *argv[], t_procid *ppid, int merge_stderr);
int shell_pipe_close(t_shell *x, t_fildes *masterfd_r, t_fildes *masterfd_w, t_procid pid, int *result);

static t_symbol *ps_default, *ps_nothing;

int C74_EXPORT main(void)
{
	shell_class = class_new("shell", (method)shell_new, (method)shell_free, sizeof(t_shell), 0L, A_GIMME, 0);
	
	class_addmethod(shell_class, (method)shell_bang,		"bang",					0);
	class_addmethod(shell_class, (method)shell_kill,		"pkill",				0);
	class_addmethod(shell_class, (method)shell_write,		"pwrite",	A_GIMME,	0);
	class_addmethod(shell_class, (method)shell_write,		"penter",	A_GIMME,	0);
	class_addmethod(shell_class, (method)shell_anything,	"anything",	A_GIMME,	0);
	class_addmethod(shell_class, (method)shell_assist,		"assist",	A_CANT,		0);
	class_addmethod(shell_class, (method)doReport,			"dblclick",	A_CANT,		0);
	
	CLASS_ATTR_CHAR(shell_class, "stderr", 0, t_shell, merge_stderr);
	CLASS_ATTR_DEFAULT_SAVE(shell_class, "stderr", 0, "0");
	CLASS_ATTR_STYLE_LABEL(shell_class, "stderr", 0, "onoff", "Merge STDERR With STDOUT");

	CLASS_ATTR_SYM(shell_class, "wd", 0, t_shell, wd);
	CLASS_ATTR_ACCESSORS(shell_class, "wd", (method)shell_attr_wd_get, (method)shell_attr_wd_set);
	CLASS_ATTR_DEFAULT_SAVE(shell_class, "wd", 0, "");
	CLASS_ATTR_STYLE_LABEL(shell_class, "wd", 0, "filefolder", "Working directory");

	CLASS_ATTR_SYM(shell_class, "shell", 0, t_shell, shell);
	CLASS_ATTR_ACCESSORS(shell_class, "shell", (method)shell_attr_shell_get, (method)shell_attr_shell_set);
	CLASS_ATTR_DEFAULT_SAVE(shell_class, "shell", 0, "");
	CLASS_ATTR_STYLE_LABEL(shell_class, "shell", 0, "file", "Shell");

	class_register(CLASS_BOX, shell_class);

	ps_default = gensym("(default)");
	ps_nothing = gensym("");

	return 0;
}

t_max_err shell_attr_wd_set(t_shell *x, void *attr, long ac, t_atom *av)
{
	char fname[MAX_FILENAME_CHARS];
	short fvol;

	if (ac && av) {
		t_symbol *pathsym = atom_getsym(av);
		if (pathsym && pathsym != ps_nothing && pathsym != ps_default
			&& !path_frompathname(atom_getsym(av)->s_name, &fvol, fname)
			&& fvol && !*fname) 
		{
			char conform[MAX_PATH_CHARS];

			if (!path_nameconform(pathsym->s_name, conform, PATH_STYLE_MAX, maxversion() >= 0x733 ? 10 : 9)) { // PATH_TYPE_MAXDB changed Max 7.3.3, oops
				x->wd = gensym(conform);
			}
			else {
				x->wd = pathsym; // unlikely
			}
		}
		else if (pathsym == ps_nothing || pathsym == ps_default)
		{
			x->wd = ps_nothing;
		}
	}
	else {
		x->wd = ps_nothing;
	}
	return MAX_ERR_NONE;
}

t_max_err shell_attr_wd_get(t_shell *x, void *attr, long *ac, t_atom **av)
{
	if (ac && av) {
		char alloc;
		if (atom_alloc(ac, av, &alloc) == MAX_ERR_NONE) {
			atom_setsym(*av, x->wd == ps_nothing ? ps_default : x->wd);
			return MAX_ERR_NONE;
		}
		return MAX_ERR_OUT_OF_MEM;
	}
	return MAX_ERR_GENERIC;
}

t_max_err shell_attr_shell_set(t_shell *x, void *attr, long ac, t_atom *av)
{
	char fname[MAX_FILENAME_CHARS];
	short fvol;

	if (ac && av) {
		t_symbol *pathsym = atom_getsym(av);
		if (pathsym && pathsym != ps_nothing && pathsym != ps_default 
			&& !path_frompathname(atom_getsym(av)->s_name, &fvol, fname)
			&& fvol && *fname) 
		{
			char conform[MAX_PATH_CHARS];
			if (!path_nameconform(pathsym->s_name, conform, PATH_STYLE_MAX, maxversion() >= 0x733 ? 10 : 9)) { // PATH_TYPE_MAXDB changed Max 7.3.3, oops
				x->shell = gensym(conform);
			}
			else {
				x->shell = pathsym; // unlikely
			}
		}
		else if (pathsym == ps_nothing || pathsym == ps_default) {
			x->shell = ps_nothing;
		}
	}
	else {
		x->shell = ps_nothing;
	}
	return MAX_ERR_NONE;
}

t_max_err shell_attr_shell_get(t_shell *x, void *attr, long *ac, t_atom **av)
{
	if (ac && av) {
		char alloc;
		if (atom_alloc(ac, av, &alloc) == MAX_ERR_NONE) {
			atom_setsym(*av, x->shell == ps_nothing ? ps_default : x->shell);
			return MAX_ERR_NONE;
		}
		return MAX_ERR_OUT_OF_MEM;
	}
	return MAX_ERR_GENERIC;
}


void shell_anything(t_shell *x, t_symbol *s, long ac, t_atom *av)
{
	if (!x->pid) {
		defer_medium(x, (method)shell_do, s, (short)ac, av);
	}
}

void shell_write(t_shell *x, t_symbol *s, long ac, t_atom *av)
{
	if (x->pid) {
		defer_medium(x, (method)shell_dowrite, s, (short)ac, av);
	}
}

void shell_atoms2text(long ac, t_atom *av, char *text)
{
	char tmp[MAX_MESSAGELEN];
	int i;
	
	for (i = 0; i < ac; i++) {
		switch(atom_gettype(av + i)) {
			case A_LONG:
				snprintf_zero(tmp, MAX_MESSAGELEN, "%"ATOM_LONG_FMT_MODIFIER"d", atom_getlong(av + i));
				break;
			case A_FLOAT:
				snprintf_zero(tmp, MAX_MESSAGELEN, "%f", atom_getfloat(av + i));
				break;
			case A_SYM:
				{
					const char *formatstr = "%s";
					const char *symstr = atom_getsym(av + i)->s_name;
					if (strchr(symstr, ' ') && *symstr != '\\' && *(symstr+1) != '\"') {
						formatstr = "\"%s\"";
					}
					snprintf_zero(tmp, MAX_MESSAGELEN, formatstr, atom_getsym(av + i)->s_name);
				}
				break;
			default:
				continue;
		}
		if (i > 0) strncat(text, " ", MAX_MESSAGELEN);
		strncat(text, tmp, MAX_MESSAGELEN);
	}
}

void shell_dowrite(t_shell *x, t_symbol *s, long ac, t_atom *av)
{
	if (x->pid && WRITE_HANDLE(x)) {
		char cmd[MAX_MESSAGELEN] = "";
		
		if (ac && av) {
			shell_atoms2text(ac, av, cmd);
		}
		if (s == gensym("penter")) {
			strncat(cmd, "\n", MAX_MESSAGELEN);
		}
		if (*cmd) {
			WRITE(WRITE_HANDLE(x), cmd);
		}
	}
}

void shell_do(t_shell *x, t_symbol *s, long ac, t_atom *av)	
{
	char cmd[MAX_MESSAGELEN] = "";
	char shellcmd[MAX_PATH_CHARS] = "sh";

	if (s) {
		char cmdtemp[MAX_PATH_CHARS] = "";
		const char *formatstr = "%s";

		if (path_getseparator(s->s_name)) {
			short cmdvol;
			char cmdfile[MAX_PATH_CHARS];
			if (!path_frompathname(s->s_name, &cmdvol, cmdfile)) { // path exists
				if (path_nameconform(s->s_name, cmdtemp, PATH_STYLE_NATIVE, PATH_TYPE_BOOT)) {
					*cmdtemp = '\0';
				}
			}
		}
		if (!*cmdtemp) {
			strncpy(cmdtemp, s->s_name, MAX_PATH_CHARS);
		}

		if (strchr(cmdtemp, ' ')) {
			formatstr = "\"%s\"";
		}

		snprintf_zero(cmd, MAX_MESSAGELEN, formatstr, cmdtemp);

		// process args
		if (ac && av) {
			strncat(cmd, " ", MAX_MESSAGELEN);
			shell_atoms2text(ac, av, cmd);
		}
	}
	else {
		strncpy(cmd, x->cmdbuf, MAX_MESSAGELEN);
	}

	if (x->shell != ps_nothing) {
		strncpy(shellcmd, x->shell->s_name, MAX_PATH_CHARS);
		// brute force and potentially wrong, assuming that any other shell will use -c to read input from the string
	}

	if (*cmd) {
#ifdef MAC_VERSION
		char *args[] = { 
			(char *)shellcmd,
			(char *)"-c", 
			(char *)cmd, 
			(char *)0 
		};
#else
		const char *shellarg = "/U /C"; // for CMD.exe, /U = unicode, /C = returning after executing string arg

		x->unicode = true;
		if (x->shell != ps_nothing) {
			strncpy(shellcmd, x->shell->s_name, MAX_PATH_CHARS);
			// brute force and potentially wrong, assuming that any other shell will use -c to read input from the string
			shellarg = "-c";
			x->unicode = false;
		}
		else {
			size_t nSize = _countof(shellcmd);
			getenv_s(&nSize, shellcmd, MAX_PATH_CHARS, "COMSPEC");
		}

		char *args[] = {
			(char *)shellcmd,
			(char *)shellarg,
			(char *)cmd, 
			(char *)0 
		};
#endif

		shell_stop(x); // kill previous command, if any
		if ((shell_pipe_open(x, &(READ_HANDLE(x)), &(WRITE_HANDLE(x)), 
			shellcmd, args,
			&x->pid, (int)x->merge_stderr)))
		{
#ifdef MAC_VERSION // read and write are the same, don't need to do this twice
			int flags;
			
			flags = fcntl(WRITE_HANDLE(x), F_GETFL, 0);
			flags |= O_NONBLOCK;
			fcntl(WRITE_HANDLE(x), F_SETFL, flags);
#endif
			strncpy(x->cmdbuf, cmd, MAX_MESSAGELEN);
			qelem_set(x->pollqfn);
		}
	}		
}

void shell_bang(t_shell *x)
{
	if (!x->pid) {
		defer_medium(x, (method)shell_do, 0, 0, 0);
	}

}

void shell_stop(t_shell *x)	
{
	qelem_unset(x->pollqfn);
	if (x->pid) {
		int rv;
#ifdef MAC_VERSION
		kill(x->pid, SIGKILL); // pipe_close_3 will do this on windows
#endif
		shell_pipe_close(x, &READ_HANDLE(x), &WRITE_HANDLE(x), x->pid, &rv);
		x->pid = 0;			
		outlet_bang(x->bangout);
	}
}

void shell_kill(t_shell *x) 
{	
	if (x->pid) {
		defer_medium(x, (method)shell_stop, NULL, 0, NULL);
	}
}

void shell_output(t_shell *x, t_symbol *s, long ac, t_atom *av)
{
	t_symbol *outsym;
	
	if (ac && av && (outsym = atom_getsym(av))) {
		// TODO: break string up into atoms?
		outlet_anything(x->textout, outsym, 0, NULL);
	}
}

Boolean shell_readline(t_shell *x)
{
	char stream[MAX_MESSAGELEN];
	char line[MAX_MESSAGELEN];
	char *lp1, *lp2;
	long bytes;
	long offset = 0;
	t_atom a;
	char *readstream = stream;
	int charsize = 1;
		
#ifdef WIN_VERSION
	WCHAR *unicodestream = NULL;

	if (x->unicode) {
		unicodestream = (WCHAR *)sysmem_newptr(MAX_MESSAGELEN * sizeof(WCHAR));
		readstream = (char *)unicodestream;
		charsize = sizeof(WCHAR);
	}
#endif

	while ((bytes = READ(READ_HANDLE(x), readstream + offset, ((MAX_MESSAGELEN-1) * charsize) - offset)) > 0) {
		readstream[bytes + offset] = '\0'; // 0-terminate.

#ifdef WIN_VERSION
		// the problem with Unicode mode is that the output might come back as Unicode or not
		// depending on which tool(s) were used. Built-in commands like DIR return Unicode,
		// but "git --version" returns ANSI. This complicates the logic of dealing with
		// incomplete lines considerably.
		if (x->unicode) {
			if (IsTextUnicode(unicodestream, bytes, NULL)) {
				int sizeinchars = bytes / sizeof(WCHAR);
				WideCharToMultiByte(CP_UTF8, 0, unicodestream, sizeinchars, stream, MAX_MESSAGELEN, NULL, NULL);
				stream[sizeinchars] = '\0';
			}
			else {
				// it's an ANSI buffer, treat unicodestream as a char* from now on
				sysmem_copyptr(unicodestream, stream, bytes);
				stream[bytes] = '\0';
				charsize = 1;
			}
		}
#endif
		lp2 = stream;
		while ((lp1 = strchr(lp2, '\n'))) { // for each complete line...
			sysmem_copyptr(lp2, line, (long)(lp1-lp2));
			line[lp1-lp2] = '\0';
			lp2 = lp1 + 1;
			atom_setsym(&a, gensym(line));
			defer_medium(x, (method)shell_output, NULL, 1, &a);
		}
		if (lp2 && *lp2) { // there's an incomplete line, rewrite it to the front of the
						   // read buffer and set the offset.
			offset = (long)strlen(lp2) * charsize;
#ifdef WIN_VERSION
			if (x->unicode) {
				if (charsize == sizeof(WCHAR)) { // it's really unicode
					MultiByteToWideChar(CP_UTF8, 0, lp2, -1, unicodestream, MAX_MESSAGELEN);
				}
				else {
					strncpy(lp2, (char *)unicodestream, MAX_MESSAGELEN);
				}
			}
			else
#endif
			{
				strncpy(line, lp2, MAX_MESSAGELEN); // temp copy
				strncpy(stream, line, MAX_MESSAGELEN);
			}
		} else {
			offset = 0;
		}
	}
	if (offset) {
		atom_setsym(&a, gensym(line));
		defer_medium(x, (method)shell_output, NULL, 1, &a);
	}
#ifdef WIN_VERSION
	if (unicodestream) {
		sysmem_freeptr(unicodestream);
	}
#endif
	return FALSE;
}

void shell_qfn(t_shell *x)
{
	if (x && READ_HANDLE(x)) {
		int rv;
		while (shell_readline(x))
			;
		// check if the process has terminated
#ifdef MAC_VERSION
		if (waitpid(x->pid, &rv, WNOHANG)) 
#else
		if (WaitForSingleObject(x->pid, 0) == WAIT_OBJECT_0)
#endif
		{
			shell_pipe_close(x, &READ_HANDLE(x), &WRITE_HANDLE(x), x->pid, &rv);
			x->pid = 0;			
			outlet_bang(x->bangout);
			return;
		}
		// otherwise, requeue
		qelem_set(x->pollqfn);
	}
}

void doReport()
{
	post("shell  _  bill orcutt (user@publicbeta.cx) / jeremy bernstein (jeremy@cycling74.com)  _  %s", __DATE__);
}

void shell_assist(t_shell *x, void *b, long m, long a, char *s)
{
	if (m==1)
		sprintf(s,"anything: shell command to exec");
	else if (m==2)
		switch (a) {

			case 0:
				strcpy(s,"stdout as symbol");
				break;

			case 1:
				strcpy(s, "bang when done");
				break;

		} 
}

void shell_free(t_shell *x)	
{
	shell_stop(x);
	
	if (x->pollqfn)
		qelem_free(x->pollqfn);
}

void *shell_new(t_symbol *s, long ac, t_atom *av)
{
	t_shell *x;

	x = (t_shell *)object_alloc(shell_class);
	if (x) {
		x->bangout = bangout(x);
		x->textout = outlet_new(x,NULL);
		x->pollqfn = qelem_new(x, (method)shell_qfn);
#ifdef MAC_VERSION
		x->fd = 0;
#else
		x->fd_r = NULL;
		x->fd_w = NULL;
		x->unicode = false;
#endif
		x->pid = 0;
		x->cmdbuf[0] = '\0';
		x->wd = ps_nothing;
		x->shell = ps_nothing;

		attr_args_process(x, (short)ac, av);
	}
	return(x);
}

/////// PIPE CODE
// http://rachid.koucha.free.fr/tech_corner/pty_pdip.html
// using posix_openpt()

int shell_pipe_open(t_shell *x, t_fildes *masterfd_r, t_fildes *masterfd_w, char *cmd, char *argv[], t_procid *ppid, int merge_stderr)
{
#ifdef MAC_VERSION
	int masterfd = posix_openpt(O_RDWR |O_NOCTTY);
	int slavefd;
	char *slavedevice;
	int rc;
	char workingdir[MAX_PATH_CHARS] = "";
	
	*ppid = 0;
	
	if (masterfd == -1
		|| grantpt(masterfd) == -1
		|| unlockpt(masterfd) == -1
		|| (slavedevice = ptsname(masterfd)) == NULL) {
		//cpost("Unable to open pty.\n");
		return 0;
	}
	
	slavefd = open(slavedevice, O_RDWR | O_NOCTTY);
	if (slavefd < 0) {
		//cpost("Unable to open slave end.\n");
		close(masterfd);
		return 0;
	}

	if (x->wd != ps_nothing) { // custom wd
		path_nameconform(x->wd->s_name, workingdir, PATH_STYLE_NATIVE, PATH_TYPE_BOOT);
	}
	else {
		char *homedir = getenv("HOME");
		if (homedir && *homedir) {
			strncpy(workingdir, homedir, MAX_PATH_CHARS);
		}
	}

	*ppid = fork();
	if (*ppid < 0) {
		close(masterfd);
		close(slavefd);
		return 0; // error
	}
	if (*ppid == 0) { // child
		struct termios orig_termios, new_termios;
		
		close(masterfd); // close the master
		
		// Save the default parameters of the slave side of the PTY
		rc = tcgetattr(slavefd, &orig_termios);
		
		// Set raw mode on the slave side of the PTY
		new_termios = orig_termios;
		cfmakeraw (&new_termios);
		tcsetattr (slavefd, TCSANOW, &new_termios);
		
		dup2(slavefd, STDIN_FILENO); // PTY becomes standard input (0)
		dup2(slavefd, STDOUT_FILENO); // PTY becomes standard output (1)
		if (merge_stderr)
			dup2(slavefd, STDERR_FILENO); // PTY becomes standard error (2)
		
		close(slavefd); // is now unnecessary
		
		setsid(); // Make the current process a new session leader
		// As the child is a session leader, set the controlling terminal to be the slave side of the PTY
		// (Mandatory for programs like the shell to make them manage correctly their outputs)
		ioctl(0, TIOCSCTTY, 1);
		if (*workingdir) {
			chdir(workingdir);
		}
		setenv("LC_ALL", "en_US.UTF-8", 1);
		execvp(cmd, argv);
	} else { // parent
		close(slavefd); // close the slave
		*masterfd_r = *masterfd_w = masterfd;
	}
	return masterfd;
#else
	SECURITY_ATTRIBUTES saAttr;
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFOW siStartInfo;
	HANDLE stdin_read = 0, stdin_write_tmp = 0, stdin_write = 0;
	HANDLE stdout_write = 0, stdout_read_tmp = 0, stdout_read = 0; 
	HANDLE stderr_write = 0;
	
	*masterfd_r = 0;
	*masterfd_w = 0;
	*ppid = 0;
	
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	
	// STDOUT
	if (!MyCreatePipeEx(&stdout_read_tmp, &stdout_write, &saAttr, 0, 0, 0, PIPE_NOWAIT)) {
		return 0;
	}
	// Dupe STDOUT to STDERR in case the child process closes STDERR for some reason
	if (!DuplicateHandle(GetCurrentProcess(), stdout_write, 
						 GetCurrentProcess(), &stderr_write, 
						 0, TRUE, DUPLICATE_SAME_ACCESS)) 
	{
		goto abkack;
	}
	// STDIN
	if (!MyCreatePipeEx(&stdin_read, &stdin_write_tmp, &saAttr, 0, 0, 0, PIPE_WAIT)) {
		goto abkack;
	}
	// Remove inheritance on the parent handles
	if (!DuplicateHandle(GetCurrentProcess(), stdout_read_tmp, 
						 GetCurrentProcess(), &stdout_read, 
						 0, FALSE, DUPLICATE_SAME_ACCESS)) 
	{
		goto abkack;
	}
	if (!DuplicateHandle(GetCurrentProcess(), stdin_write_tmp, 
						 GetCurrentProcess(), &stdin_write, 
						 0, FALSE, DUPLICATE_SAME_ACCESS)) 
	{
		goto abkack;
	}
	// Close the temp handles
	CLEAN_CLOSEHANDLE(stdout_read_tmp);
	CLEAN_CLOSEHANDLE(stdin_write_tmp);
	// Prep the process creation
	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFOW));
	siStartInfo.cb = sizeof(STARTUPINFOW);
	siStartInfo.hStdError = stderr_write;
	siStartInfo.hStdOutput = stdout_write;
	siStartInfo.hStdInput = stdin_read;
	siStartInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	siStartInfo.wShowWindow = SW_HIDE;
	
	if (1) {
		char newcmd[MAX_MESSAGELEN];
		char workingdir[MAX_PATH];
		char cmdtemp[MAX_PATH_CHARS];
		char wdtemp[MAX_PATH_CHARS];
		WCHAR wnewcmd[MAX_MESSAGELEN];
		WCHAR wworkingdir[MAX_PATH];
		char *w;
		char **arg = argv;

		if (*arg) {
			char quotes = false;

			// 1st arg: shell
			strncpy(cmdtemp, *arg, MAX_PATH_CHARS);
			path_nameconform(cmdtemp, newcmd, PATH_STYLE_NATIVE, PATH_TYPE_ABSOLUTE);

			// 2nd arg: flag to shell
			++arg;
			if (*arg) {
				strncat(newcmd, " ", MAX_MESSAGELEN);
				strncat(newcmd, *arg, MAX_MESSAGELEN);
			}

			// addl args: cmd to execute
			while (++arg && *arg) {
				strncat(newcmd, " ", MAX_MESSAGELEN);
				// don't quote in CMD.exe (I will note that quoting in CreateProcess is a catastrophe)
				if (!quotes && !x->unicode) {
					strncat(newcmd, "\'", MAX_MESSAGELEN);
					quotes = true;
				}
				strncat(newcmd, *arg, MAX_MESSAGELEN);
			}
			if (quotes) {
				strncat(newcmd, "\'", MAX_MESSAGELEN);
			}
		}
		MultiByteToWideChar(CP_UTF8, 0, newcmd, (int)(strlen(newcmd) + 1), wnewcmd, MAX_MESSAGELEN);
		
		// WCHAR working dir
		if (x->wd != ps_nothing) {
			strncpy(wdtemp, x->wd->s_name, MAX_PATH_CHARS);
			path_nameconform(wdtemp, workingdir, PATH_STYLE_NATIVE, PATH_TYPE_ABSOLUTE);
			MultiByteToWideChar(CP_UTF8, 0, workingdir, (int)(strlen(workingdir) + 1), wworkingdir, MAX_PATH);
		}
		else { // use $HOME as the default WD
			size_t nSize = _countof(wworkingdir);
			if (!_wgetenv_s(&nSize, wworkingdir, (size_t)MAX_PATH, L"HOMEPATH")) {
				strncpy(cmdtemp, cmd, MAX_PATH_CHARS);
				path_nameconform(cmdtemp, workingdir, PATH_STYLE_NATIVE, PATH_TYPE_ABSOLUTE);
				if (w = strrchr(workingdir, '\\')) {
					*w = '\0';
				}
				MultiByteToWideChar(CP_UTF8, 0, workingdir, (int)(strlen(workingdir) + 1), wworkingdir, MAX_PATH);
			}
		}

		if (!CreateProcessW(NULL, wnewcmd, NULL, NULL, TRUE, 
			/*DETACHED_PROCESS | */ CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_PROCESS_GROUP,
						   NULL, wworkingdir, &siStartInfo, &piProcInfo)) 
		{
			goto abkack;
		}
	}
	
	// Close all the dead handles
	CLEAN_CLOSEHANDLE(stdout_write);
	CLEAN_CLOSEHANDLE(stdin_read);
	CLEAN_CLOSEHANDLE(stderr_write);
	
	CLEAN_CLOSEHANDLE(piProcInfo.hThread);
	
	// we did it!
	*masterfd_r = stdout_read;
	*masterfd_w = stdin_write;
	
	*ppid = piProcInfo.hProcess;
	
	return 1;
abkack:
	CLEAN_CLOSEHANDLE(stdout_write);
	CLEAN_CLOSEHANDLE(stdout_read_tmp);
	CLEAN_CLOSEHANDLE(stdout_read);
	
	CLEAN_CLOSEHANDLE(stdin_read);
	CLEAN_CLOSEHANDLE(stdin_write_tmp);
	CLEAN_CLOSEHANDLE(stdin_write);
	
	CLEAN_CLOSEHANDLE(stderr_write);
	return 0;
#endif
}

int shell_pipe_close(t_shell *x, t_fildes *masterfd_r, t_fildes *masterfd_w, t_procid pid, int *result)
{
#ifdef MAC_VERSION
    int status;
	
    if (result) *result=255;
	if (masterfd_r && *masterfd_r) {
		close(*masterfd_r);
		*masterfd_r = 0;
	}
	if (masterfd_w && *masterfd_w) {
		close(*masterfd_w);
		*masterfd_w = 0;
	}
	
	if (!pid) return 0;
    
	while (waitpid((pid_t)pid, &status, 0/*WNOHANG | WUNTRACED*/) < 0) {
		if (EINTR!=errno) 
			return 0;
	}
    if (result && WIFEXITED(status)) {
		*result=WEXITSTATUS(status);
	}
#else
	if (masterfd_r) {
		CLEAN_CLOSEHANDLE(*masterfd_r);
	}
	if (masterfd_w) {
		CLEAN_CLOSEHANDLE(*masterfd_w);
	}
	if (pid) {
		TerminateProcess(pid, 0);
		WaitForSingleObject(pid, INFINITE); // we could do this, but it's probably not necessary
		CLEAN_CLOSEHANDLE(pid);
	}
#endif
	return 0;
}
