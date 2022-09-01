#define SYSCALL_DEFINE3(name, b, cmd, x, uattr, y, size)	\
long lauras_sys_##name(b cmd, x uattr, y size)


SYSCALL_DEFINE3(bpf, int, cmd, unsigned int *, uattr, unsigned int, size)
{
return 7;
}

int main() {
	return lauras_sys_bpf(5, 0, 112);
}
