#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>

#pragma GCC diagnostic ignored "-Wunused-parameter"

#define STUB_ONLY {                             \
	__ensure(!"STUB_ONLY function was called"); \
	__builtin_unreachable();                    \
}

namespace mlibc {

void sys_libc_log(const char *message) STUB_ONLY

void sys_libc_panic() STUB_ONLY

void sys_exit(int status) STUB_ONLY

#ifndef MLIBC_BUILDING_RTLD

[[noreturn]] void sys_thread_exit() STUB_ONLY

int sys_clone(void *tcb, pid_t *pid_out, void *stack) STUB_ONLY

int sys_kill(pid_t pid, int signal) STUB_ONLY

int sys_tcgetattr(int fd, struct termios *attr) STUB_ONLY

int sys_tcsetattr(int fd, int optional_action, const struct termios *attr) STUB_ONLY

#endif

int sys_tcb_set(void *pointer) STUB_ONLY

#ifndef MLIBC_BUILDING_RTLD

int sys_ppoll(struct pollfd *fds, int nfds, const struct timespec *timeout,
		const sigset_t *sigmask, int *num_events) STUB_ONLY

int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) STUB_ONLY

int sys_pselect(int nfds, fd_set *read_set, fd_set *write_set,
		fd_set *except_set, const struct timespec *timeout,
		const sigset_t *sigmask, int *num_events) STUB_ONLY

#endif

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) STUB_ONLY

int sys_futex_wake(int *pointer) STUB_ONLY

#ifndef MLIBC_BUILDING_RTLD

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) STUB_ONLY

int sys_isatty(int fd) STUB_ONLY

int sys_getcwd(char *buffer, size_t size) STUB_ONLY

#endif

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) STUB_ONLY

int sys_open(const char *path, int flags, mode_t mode, int *fd) STUB_ONLY

#ifndef MLIBC_BUILDING_RTLD

int sys_open_dir(const char *path, int *handle) STUB_ONLY

int sys_read_entries(int fd, void *buffer, size_t max_size, size_t *bytes_read) STUB_ONLY

#endif

int sys_close(int fd) STUB_ONLY

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) STUB_ONLY

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) STUB_ONLY

#ifndef MLIBC_BUILDING_RTLD

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) STUB_ONLY

int sys_readlink(const char *path, void *data, size_t max_size, ssize_t *length) STUB_ONLY

int sys_link(const char *old_path, const char *new_path) STUB_ONLY

int sys_linkat(int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags) STUB_ONLY

int sys_unlinkat(int fd, const char *path, int flags) STUB_ONLY

int sys_fchmod(int fd, mode_t mode) STUB_ONLY

int sys_rmdir(const char *path) STUB_ONLY

#endif

int sys_vm_map(void *hint, size_t size, int prot, int flags,
			   int fd, off_t offset, void **window) STUB_ONLY

int sys_vm_unmap(void *pointer, size_t size) STUB_ONLY

#ifndef MLIBC_BUILDING_RTLD

int sys_vm_protect(void *pointer, size_t size, int prot) STUB_ONLY

#endif

int sys_anon_allocate(size_t size, void **pointer) STUB_ONLY

int sys_anon_free(void *pointer, size_t size) STUB_ONLY

#ifndef MLIBC_BUILDING_RTLD

pid_t sys_getpid() STUB_ONLY

pid_t sys_getppid() STUB_ONLY

uid_t sys_getuid() STUB_ONLY

uid_t sys_geteuid() STUB_ONLY

gid_t sys_getgid() STUB_ONLY

int sys_setgid(gid_t gid) STUB_ONLY

pid_t sys_getpgid(pid_t pid, pid_t *pgid) STUB_ONLY

gid_t sys_getegid() STUB_ONLY

int sys_setpgid(pid_t pid, pid_t pgid) STUB_ONLY

int sys_ttyname(int fd, char *buf, size_t size) STUB_ONLY

int sys_clock_get(int clock, time_t *secs, long *nanos) STUB_ONLY

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) STUB_ONLY

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) STUB_ONLY

int sys_access(const char *path, int mode) STUB_ONLY

int sys_pipe(int *fds, int flags) STUB_ONLY

int sys_chdir(const char *path) STUB_ONLY

int sys_mkdir(const char *path, mode_t mode) STUB_ONLY

int sys_mkdirat(int dirfd, const char *path, mode_t mode) STUB_ONLY

int sys_socket(int domain, int type_and_flags, int proto, int *fd) STUB_ONLY

int sys_socketpair(int domain, int type_and_flags, int proto, int *fds) STUB_ONLY

int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) STUB_ONLY

int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) STUB_ONLY

int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags) STUB_ONLY

int sys_getsockopt(int fd, int layer, int number,
		void *__restrict buffer, socklen_t *__restrict size) STUB_ONLY

int sys_setsockopt(int fd, int layer, int number,
		const void *buffer, socklen_t size) STUB_ONLY

int sys_msg_recv(int sockfd, struct msghdr *hdr, int flags, ssize_t *length) STUB_ONLY

int sys_peername(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length) STUB_ONLY

int sys_listen(int fd, int backlog) STUB_ONLY

int sys_inotify_create(int flags, int *fd) STUB_ONLY

int sys_fork(pid_t *child) STUB_ONLY

int sys_execve(const char *path, char *const argv[], char *const envp[]) STUB_ONLY

int sys_fcntl(int fd, int request, va_list args, int *result) STUB_ONLY

int sys_dup(int fd, int flags, int *newfd) STUB_ONLY

int sys_dup2(int fd, int flags, int newfd) STUB_ONLY

int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) STUB_ONLY

int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) STUB_ONLY

int sys_signalfd_create(sigset_t mask, int flags, int *fd) STUB_ONLY

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) STUB_ONLY

int sys_getgroups(size_t size, const gid_t *list, int *_ret) STUB_ONLY

int sys_mount(const char *source, const char *target, const char *fstype, unsigned long flags, const void *data) STUB_ONLY

int sys_umount2(const char *target, int flags) STUB_ONLY

int sys_gethostname(char *buffer, size_t bufsize) STUB_ONLY

int sys_sethostname(const char *buffer, size_t bufsize) STUB_ONLY

int sys_sleep(time_t *secs, long *nanos) STUB_ONLY

int sys_getitimer(int, struct itimerval *) STUB_ONLY

int sys_setitimer(int, const struct itimerval *, struct itimerval *) STUB_ONLY

#endif

} // namespace mlibc
