#include "Dimm.h"

// target_task_name 进程名
int imm_begin(char *target_task_name)
{
        int ret;
        char *task_name = target_task_name;

        printk(KERN_ALERT "#imm_begin start#\n"); // printk类同print，不过printk运行于内核态，printf运行于用户态。
        /* KERN_ALERT 消息打印级别：数字越小，级别越高。
         * #define KERN_ALERT "<1>" // action must be taken immediately
         * From: http://www.360doc.com/content/14/0212/10/15515903_351827805.shtml
         */

        if (target_task_name[0] == '1') {
                printk(KERN_ALERT "nothing to do\n");
        }

        ret = do_code_hash(task_name);

        printk(KERN_ALERT "procfs_buffer = %s\n", procfs_buffer);
        printk(KERN_ALERT "task_name = %s\n", task_name);
        printk(KERN_ALERT "#imm_begin end#\n");

        return ret;
}


/* read the target process' userspace */
int read_process_space(struct task_struct *tsk, unsigned long addr, char *buf, int len, int write)
{
	struct mm_struct *mm;	// memeory manager
        /* mm_strcut： 用来描述一个进程的虚拟地址空间。
	 * From: http://lxr.free-electrons.com/source/include/linux/mm_types.h?v=3.18#L345 - 457
	 */
	struct vm_area_struct *vma;
        /* vm_area_struct： The first cache line has the info for VMA tree walking.
	 * From: http://lxr.free-electrons.com/source/include/linux/mm_types.h?v=3.18#L247 - 311
	 */
	struct page *page;
        /* page： From: http://lxr.free-electrons.com/source/tools/virtio/linux/kernel.h?v=3.18#L26 - 28
	 */
        char *old_buf = buf;
        int acc_vm_count = 0;	// accumulator of virtual memory count
	
        mm = get_task_mm(tsk); // get a reference to a task's mm
	/* Grab a reference to a task's mm, if it is not already going away
	 * From: http://lxr.free-electrons.com/source/include/linux/sched.h?v=3.18#L2417
	 * Impl: http://lxr.free-electrons.com/source/kernel/fork.c?v=3.18#L710 - 724
	 */
	if (!mm)
		return 0;
        /* Returns %NULL if the task has no mm.  Checks PF_KTHREAD
         * (meaning this kernel workthread has transiently adopted a user mm with use_mm,
         * to do its AIO) is not set and if so returns a reference to it,
         * after bumping up the use count.
         * User must release the mm via mmput() after use.
         * Typically used by /proc and ptrace.
	 */

        //  忽略错误，只看拷贝出了多少内容，返回
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		acc_vm_count++;
		
                ret = get_user_pages(tsk, mm, addr, 1, write, 1, &page, &vma); // pin user pages in memory,Returns number of pages pinned
                /* addr: start user addr; 1: nr_pages from start to pin; 1:force write; page: pointers to the pages pinned
		 * Impl 1: http://lxr.free-electrons.com/source/mm/gup.c?v=3.18#L637
		 * Impl 2: http://lxr.free-electrons.com/source/mm/nommu.c?v=3.18#L199
		 */
		if (ret <= 0)
			break;
		/* Returns number of pages pinned. This may be fewer than the number
		 * requested. If nr_pages is 0 or negative, returns 0. If no pages
		 * were pinned, returns -errno. Each page returned must be released
		 * with a put_page() call when it is finished with. vmas will only
		 * remain valid while mmap_sem is held.
		 */

		bytes = len;
                offset = addr & (PAGE_SIZE - 1);
                if (bytes > PAGE_SIZE - offset)
			bytes = PAGE_SIZE - offset;
		maddr = kmap(page); 
                /* 将高端内存中的页框映射到内核虚拟地址中： 永久内核映射
                 * (Takes a struct page from high memory and maps it into low memory.
                 *  The address returned is the virtual address of the mapping)
                 * From 1: http://lxr.free-electrons.com/source/arch/mips/mm/highmem.c?v=3.18#L13
		 * From 2: http://lxr.free-electrons.com/source/arch/frv/mm/highmem.c?v=3.18#L14
		 * From: thers're many. Which is the right version?
		 */
		memcpy(buf, maddr + offset, bytes);
		/* void *memcpy(void *dest, const void *src, size_t n);
		 * 从源src所指的内存地址的起始位置开始拷贝n个字节到目标dest所指的内存地址的起始位置中
		 * From: string.h
		 */
		kunmap(page);
		/* From 1: http://lxr.free-electrons.com/source/arch/frv/mm/highmem.c?v=3.18#L24
		 * From 2: http://lxr.free-electrons.com/source/arch/mips/mm/highmem.c?v=3.18#L27
		 * From: thers're many. Which is the right version?
		 */
                page_cache_release(page); // 页缓存释放
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}

        mmput(mm);
        /* mmput gets rid of the mappings and all user-space
         * (Decrement the use count and release all resources for an mm)
         * Decrement the use count and release all resources for an mm.
	 * From: http://lxr.free-electrons.com/source/kernel/fork.c?v=3.18#L649
	 */
	
	return buf - old_buf;
}

/*
 * get the content to be hashed
 * @tsk：待hash的PCB
 * @src：hash起始点
 * @dst：待hash的字节流起点
 * @len：待hash的字节流长度
 */
int get_hash_content(struct task_struct *tsk, unsigned long src, char *dst, int len)
{
        int copied = 0;
        int cshu = 0;
        char *dst_new = dst; // new的新目的地址
	
	while (len > 0) {
		char buf[128];
		int this_len, retval;		

		cshu++;
		this_len = (len > sizeof(buf)) ? sizeof(buf) : len;
		
		retval = read_process_space(tsk, src, buf, this_len, 0);	// user-defined above
		if (!retval) {
			if (copied)
				break;
			return -EIO;
		}
		
                if (DEBUG == 1) {
			printk(KERN_ALERT "get_hash_content step1\n");
			printk(KERN_ALERT "retval is %d\n",retval);	
		}
		memcpy(dst_new, buf, retval);
		
                if (DEBUG == 1) {
			printk(KERN_ALERT "get_hash_content step2\n");		
		}
		copied += retval;
		src += retval;
		dst_new += retval;
		len -= retval;                  	
	}
	return copied;
}

/* compute the content's hash 
 * @hash_start 	:start of the content to be hashed
 * @count		:size (correspond to hash_type)
 * @hash_type	:=1 means do process's content hash; =2 means do argv's hash
 */	
int compute_p_hash(struct task_struct *p, unsigned long hash_start, size_t count, int hash_type)
{
	int i;
	int times_count = 0;
	int arg_lenth = count;
	u8 PCRValue[20];
        /* 页面控制暂存器 (PCR - Page Control Register)
         * #define u8      unsigned char	// OS-Driver Definitions
         * From: http://lxr.free-electrons.com/source/drivers/net/fddi/skfp/h/targetos.h?v=3.18#L92
         */

	size_t count_thistime;
	char *hash_content = NULL;
	struct crypto_hash *tfm;
        /* Transforms: user-instantiated objects which encapsulate algorithms and core processing logic.
         * Managed via crypto_alloc_tfm() and crypto_free_tfm(), as well as the various helpers below.
	 * From: http://lxr.free-electrons.com/source/drivers/staging/rtl8192e/rtl8192e/rtl_crypto.h?v=3.18#L186
	 */

	struct scatterlist sg;
	struct hash_desc desc;
	
	char hash_string_value[41] = {'0'}; 
	int ret = 0;

	printk(KERN_ALERT "#compute_p_hash start#\n");
        printk(KERN_ALERT "hash_type = %d\n", hash_type);

	tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	/* Locate algorithm and allocate transform
	 * From: http://lxr.free-electrons.com/source/crypto/api.c?v=3.18#L530
	 */
	if (tfm == NULL) {
		ret = -1;
		goto out;
	}

	desc.tfm = tfm;
	desc.flags = 0;
	crypto_hash_init(&desc);
	/* crypto_hash_init() - (re)initialize message digest handle
	 * @desc: cipher request handle that to be filled by caller --
	 *        desc.tfm is filled with the hash cipher handle;
	 *        desc.flags is filled with either CRYPTO_TFM_REQ_MAY_SLEEP or 0.
	 *
	 * The call (re-)initializes the message digest referenced by the hash cipher
	 * request handle. Any potentially existing state created by previous
	 * operations is discarded.
	 *
         * Return: 0 if the message digest initialization was successful;
         *        < 0 if an error occurred
	 * From: http://lxr.free-electrons.com/source/include/linux/crypto.h#L2242·
	 */
	
	sg_init_one(&sg, hash_string_value, 40);
	/* Initialize a single entry sg list
	 * From: http://lxr.free-electrons.com/source/lib/scatterlist.c#L125
	 */
        crypto_hash_init(&desc);

	hash_content = kmalloc(PAGE_SIZE, GFP_KERNEL);
        /* allocate memory： From: http://lxr.free-electrons.com/source/include/linux/slab.h?v=3.18#L412
	 */
	if (!hash_content) {
                printk(KERN_ALERT "no memory for read buffer\n");
		ret = -2;
                goto out; /* invalidate pcr */
	}
	
        while (count > 0) {
                count_thistime = (count < PAGE_SIZE) ? count : PAGE_SIZE;
                ret = get_hash_content(p, hash_start, hash_content, count_thistime); // hash_start：加密起始点，hash_content：待加密的字节流
                printk(KERN_ALERT "hash_content = %s, count_thistime = %ld\n", hash_content, count_thistime);
		if (hash_type == 2) {
                        printk(KERN_ALERT "args is %s\n", hash_content);
                        memcpy(measurement_output.argv + times_count * PAGE_SIZE, hash_content, count);
                        ++times_count;
		}
		
		hash_start = hash_start + ret;
		count = count - ret;
		crypto_hash_update(&desc, &sg, 40);
		/* crypto_hash_update() - add data to message digest for processing
		 * @desc: cipher request handle
                 * @sg: scatter / gather list pointing to the data to be added to the message digest
		 * @nbytes: number of bytes to be processed from @sg
		 *
		 * Updates the message digest state of the cipher handle pointed to by the
		 * hash cipher request handle with the input data pointed to by the scatter/gather list.
		 *
                 * Return: 0 if the message digest update was successful;
                 *         < 0 if an error occurred
		 * From: http://lxr.free-electrons.com/source/include/linux/crypto.h#L2261
		 */
	}
	
        if (hash_type == 2) { // format the argv, deal with '\0'
                i=0;
		while (i < arg_lenth - 1) {
                        if((measurement_output.argv[i] == '\0') || (measurement_output.argv[i] == ' '))
			measurement_output.argv[i] = ' ';
                        ++i;
		}
		printk(KERN_ALERT "format arg is %s\n", measurement_output.argv);
	}
	
        kfree(hash_content); // 释放内核中分配的内存，与kmalloc相对
        crypto_hash_final(&desc, PCRValue);
        /* crypto_hash_final() - calculate message digest
         * @desc: cipher request handle
         * @out: message digest output buffer -- The caller must ensure that the out
         *       buffer has a sufficient size (e.g. by using the crypto_hash_digestsize
         *       function).
         *
         * Finalize the message digest operation and create the message digest
         * based on all data added to the cipher handle. The message digest is placed
         * into the output buffer.
         *
         * Return: 0 if the message digest creation was successful;
         *         < 0 if an error occurred
         * From: http://lxr.free-electrons.com/source/include/linux/crypto.h#L2282
         *       http://lxr.free-electrons.com/source/drivers/staging/rtl8192e/rtl8192e/rtl_crypto.h?v=3.18#L284
         */
  
	printk(KERN_ALERT "hash_string_value=%s\n", hash_string_value);
        for (i = 0; i < 20; ++i) {
                sprintf(hash_string_value + i * 2, "%02x", PCRValue[i]);
	}
	printk(KERN_ALERT "hash_string_value=%s\n", hash_string_value);
	if (hash_type == 1)
                strncpy(measurement_output.target_hash, hash_string_value, 40);
	strncpy(measurement_output.argv_hash, hash_string_value, 40);

	printk(KERN_ALERT "process hash is %s\n", hash_string_value);
	printk(KERN_ALERT "#compute_p_hash end#\n");
out:
	return ret;						      
}

/* 对module进行加密 */
int compute_m_hash(struct module *mod)
{
        /* struct module_ref - per cpu module reference counts
         * struct module - ?
         * From: http://lxr.free-electrons.com/source/include/linux/module.h?v=3.18#L37 - 378
         */
        struct crypto_hash *tfm;
        char *hash_content = mod->module_core;
        char hash_string_value[41] = {'0'};
        int count = mod->core_text_size;
        int ret = 0;
        size_t count_thistime;
        u8 PCRValue[20];
        int i;

        struct scatterlist sg;
        struct hash_desc desc;

        tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
        if (tfm == NULL)
        {
                ret = -1;
                return ret;
        }

        desc.tfm = tfm;
        desc.flags = 0;
        crypto_hash_init(&desc);

        sg_init_one(&sg, hash_string_value, 40);
        crypto_hash_init(&desc);

        printk (KERN_ALERT "error 1 in compute hash\n");
        if (!hash_content) {
                printk (KERN_ALERT "no memory for read buffer\n");
                ret = -2;
                goto out; /* invalidate pcr */
        }

        printk (KERN_ALERT "error 2 in compute hash\n");
        while (count > 0) {
            count_thistime = (count > PAGE_SIZE) ? PAGE_SIZE : count;
            count = count - count_thistime;
            hash_content = hash_content + count_thistime;
            crypto_hash_update(&desc, &sg, 40);	// As mentioned in the prev function.
        }
        printk (KERN_ALERT "error 4 in compute hash\n");
        crypto_hash_final(&desc, PCRValue);

        for (i = 0; i < 20; i++)
                sprintf(hash_string_value + i * 2, "%02x", PCRValue[i]);

        printk(KERN_ALERT "hash is %s\n", hash_string_value);
        strncpy(measurement_output.target_hash, hash_string_value, 40);

out:
        return ret;
}


int do_code_hash(char* target_task_name) 
{
        int ret = 0;
        size_t code_len; /* lenth of code */
        size_t argv_len; /* lenth of input */

        unsigned long st_code, ed_code;
        unsigned long st_argv, ed_argv;

        struct module *mod;
        static LIST_HEAD(modules); // http://lxr.free-electrons.com/source/scripts/kconfig/list.h?v=3.18#L30
        struct task_struct *p; // pointer used to find target process in process list

        rwlock_t tasklist;
        rwlock_init(&tasklist); // http://lxr.free-electrons.com/source/include/linux/rwlock.h#L20

        read_lock(&tasklist); // = raw_read_lock(lock) http://lxr.free-electrons.com/source/include/linux/rwlock.h?v=3.18#L65
        /* If lockdep is enabled then we use the non-preemption spin-ops
         * even on CONFIG_PREEMPT, because lockdep assumes that interrupts are
         * not re-enabled during lock-acquire (which the preempt-spin-ops do):
         * From: http://lxr.free-electrons.com/source/include/linux/rwlock_api_smp.h?v=3.18#L146
         */

        printk(KERN_ALERT "#do_code_hash start#\n");
        for_each_process(p) // Macro func: http://lxr.free-electrons.com/source/include/linux/sched.h?v=3.18#L2470
        if (strcmp(p->comm, target_task_name) == 0)
                break;

        read_unlock(&tasklist);

        /* see if p is target task or just at the end of task queue */
        if (strcmp(p->comm, target_task_name) != 0)
                goto is_module;

        /* get the start and the end of the code */
        /* from task's mm_struct */
        st_code = p->mm->start_code;
        ed_code = p->mm->end_code;
        st_argv = p->mm->arg_start;
        ed_argv = p->mm->arg_end;

        code_len = (int)(ed_code - st_code);
        argv_len = (int)(ed_argv - st_argv);

        /* now fill the strct measurement_output */
        memset(&measurement_output, 0, sizeof(measurement_output));
        strcpy(measurement_output.target_name, target_task_name);

        compute_p_hash(p, st_code, code_len, 1); /*fill target_hash*/
        compute_p_hash(p, st_argv, argv_len, 2); /*fill argv_hash*/

        get_timestamp(); /*fill time_stamp*/
        printk(KERN_ALERT "#do_code_hash end#\n");
        return ret;
	
is_module:

        printk(KERN_ALERT "checking module  %s\n", __this_module.name);

        list_for_each_entry(mod, *(&THIS_MODULE->list.prev), list) {
                /* Macro func From: http://lxr.free-electrons.com/source/scripts/kconfig/list.h?v=3.18#L48
                 */
                printk(KERN_ALERT "checking module  %s\n", mod->name);
                if (strcmp(mod->name, target_task_name) == 0)
                        break;
        }

        if (strcmp(mod->name, target_task_name) != 0) {
                printk(KERN_ALERT "request module is %s\n", target_task_name);
                printk(KERN_ALERT "but no module in memory\n");
                memset(procfs_buffer, 0, PROCFS_MAX_SIZE);
                ret = -2;
                return ret;
        }

        if (compute_m_hash(mod) != 0) {
                printk(KERN_ALERT "fail to do module hash\n");
                ret = -3;
                return ret;
        }

        get_timestamp();
        return 0;
}


/* 系统时间转化为日历时间（因为内核中只能获取时钟数，但没有直接的库函数将其转换为常用的时间格式） */
struct caltime sec2cal(time_t cur_second)
{
        struct caltime cur_time;
        int is_leap_year;
        int year;

        /* Fill the data into struct cur_time */
        cur_time.nowsec = (cur_second % 60);
        cur_time.nowmin = (cur_second - cur_time.nowsec) / 60 % 60;
        cur_time.nowh = (cur_second - cur_time.nowmin * 60 - cur_time.nowsec - 8 * 3600) / 3600 % 24 ;
        cur_time.nowd = (cur_second - cur_time.nowh * 3600 - cur_time.nowmin * 60 - cur_time.nowsec) / 86400;
        cur_time.nowy = 1970;

        while (cur_time.nowd > 365) {
                year = cur_time.nowy + 1;
                if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
                        is_leap_year = 1;
                else
                        is_leap_year = 0;

                if (is_leap_year==1) {
                        cur_time.nowd = cur_time.nowd - 366;
                        cur_time.nowy += 1;
                } else {
                        cur_time.nowd = cur_time.nowd - 365;
                        cur_time.nowy += 1;
                }
        }

        if ((cur_time.nowy % 4 == 0 && cur_time.nowy % 100 != 0) || (cur_time.nowy %400 == 0)) { /* cur_time.nowy is a leap year */
                if (cur_time.nowd <= 31)
                        cur_time.nowm = 1;

                if (cur_time.nowd >31 && cur_time.nowd <= 60) {
                        cur_time.nowm = 2;
                        cur_time.nowd = cur_time.nowd - 31;
                }
                if (cur_time.nowd > 60 && cur_time.nowd <= 91) {
                        cur_time.nowm = 3;
                        cur_time.nowd = cur_time.nowd - 60;
                }
                if (cur_time.nowd > 91 && cur_time.nowd < 121) {
                        cur_time.nowm = 4;
                        cur_time.nowd = cur_time.nowd - 91;
                }
                if (cur_time.nowd > 121 && cur_time.nowd <= 152) {
                        cur_time.nowm = 5;
                        cur_time.nowd = cur_time.nowd - 121;
                }
                if (cur_time.nowd > 152 && cur_time.nowd <= 182) {
                        cur_time.nowm = 6;
                        cur_time.nowd = cur_time.nowd - 152;
                }
                if (cur_time.nowd > 182 && cur_time.nowd <= 213) {
                        cur_time.nowm = 7;
                        cur_time.nowd = cur_time.nowd - 182;
                }
                if (cur_time.nowd > 213 && cur_time.nowd <= 244) {
                        cur_time.nowm = 8;
                        cur_time.nowd = cur_time.nowd - 213;
                }
                if (cur_time.nowd > 244 && cur_time.nowd <= 274) {
                        cur_time.nowm = 9;
                        cur_time.nowd = cur_time.nowd - 244;
                }
                if (cur_time.nowd > 274 && cur_time.nowd <= 305) {
                        cur_time.nowm = 10;
                        cur_time.nowd = cur_time.nowd - 274;
                }
                if (cur_time.nowd > 305 && cur_time.nowd <= 335) {
                        cur_time.nowm = 11;
                        cur_time.nowd = cur_time.nowd - 305;
                }
                if (cur_time.nowd > 335) {
                        cur_time.nowm = 12;
                        cur_time.nowd = cur_time.nowd - 335;
                }
        } else {
                if (cur_time.nowd <= 31)
                        cur_time.nowm = 1;

                if (cur_time.nowd > 31 && cur_time.nowd <= 59) {
                        cur_time.nowm = 2;
                        cur_time.nowd = cur_time.nowd - 31;
                }
                if (cur_time.nowd > 59 && cur_time.nowd <= 90) {
                        cur_time.nowm = 3;
                        cur_time.nowd = cur_time.nowd - 59;
                }
                if (cur_time.nowd > 90 && cur_time.nowd <= 120) {
                        cur_time.nowm = 4;
                        cur_time.nowd = cur_time.nowd - 90;
                }
                if (cur_time.nowd > 120 && cur_time.nowd <= 151) {
                        cur_time.nowm = 5;
                        cur_time.nowd = cur_time.nowd - 120;
                }
                if (cur_time.nowd > 151 && cur_time.nowd <= 181) {
                        cur_time.nowm = 6;
                        cur_time.nowd = cur_time.nowd - 151;
                }
                if (cur_time.nowd > 181 && cur_time.nowd <= 211) {
                        cur_time.nowm = 7;
                        cur_time.nowd = cur_time.nowd - 181;
                }
                if (cur_time.nowd > 211 && cur_time.nowd <= 243) {
                        cur_time.nowm = 8;
                        cur_time.nowd = cur_time.nowd - 212;
                }
                if (cur_time.nowd > 243 && cur_time.nowd <= 273) {
                        cur_time.nowm = 9;
                        cur_time.nowd = cur_time.nowd - 243;
                }
                if (cur_time.nowd > 273 && cur_time.nowd <= 304) {
                        cur_time.nowm = 10;
                        cur_time.nowd = cur_time.nowd - 273;
                }
                if (cur_time.nowd > 304 && cur_time.nowd <= 33334) {
                        cur_time.nowm = 11;
                        cur_time.nowd = cur_time.nowd - 304;
                }
                if (cur_time.nowd > 334) {
                        cur_time.nowm = 12;
                        cur_time.nowd = cur_time.nowd - 334;
                }
        }
        cur_time.nowd += 1;
        printk("%ld/%ld/%ld %ld:%ld:%ld\n", cur_time.nowy, cur_time.nowm, cur_time.nowd,
                cur_time.nowh, cur_time.nowmin, cur_time.nowsec);
        return cur_time;
}


/* 计算并格式化时间戳 */
int get_timestamp()
{
        struct caltime now;
        struct timeval *tv;

        tv = kmalloc(sizeof(struct timeval), GFP_KERNEL);	// kmalloc() As mentioned above.
        do_gettimeofday(tv);
        /* Returns the time of day in a timeval
         * From: http://lxr.free-electrons.com/source/kernel/time/timekeeping.c?v=3.18#L695
         */

        tv->tv_sec = tv->tv_sec + 16 * 3600;
        printk("tv in kernel is %ld\n", tv->tv_sec);
        now = sec2cal(tv->tv_sec); // sec2cal - User Defined Func
        sprintf(measurement_output.time_stamp, "%ld/%ld/%ld %ld:%ld:%ld",
                now.nowy, now.nowm, now.nowd, now.nowh, now.nowmin, now.nowsec);
        return 0;
}

/* 将内核空间的struct measurement_member结构拷入用户空间的buffer中 */
static ssize_t procfs_read(struct file *filp,   // see include/linux/fs.h
                              char *buffer,     // buffer to fill with data
                              size_t length,    // length of the buffer
                              loff_t * offset)
{
        if (copy_to_user(buffer, &measurement_output, sizeof(measurement_output))) {	// http://lxr.free-electrons.com/source/arch/x86/include/asm/uaccess.h?v=3.18#L723
		return -EFAULT;
	}
	printk(KERN_INFO "procfs_read: read %ld bytes\n", sizeof(measurement_output));    //fix warning: sizeof返回long unsigned int
	return sizeof(measurement_output);       /* Return the number of bytes "read" */
}


/*将用户空间的buffer拷入内核空间的procfs_buffer中*/
static ssize_t
procfs_write(struct file *file, const char *buffer, size_t len, loff_t * off)
{
        if (len < PROCFS_MAX_SIZE) {
                procfs_buffer_size = len;
        } else {
                procfs_buffer_size = PROCFS_MAX_SIZE;
        }

        memset(&measurement_output, 0, sizeof(measurement_output));

        memset(procfs_buffer, 0, PROCFS_MAX_SIZE);
        if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
                return -EFAULT;
        }
        printk(KERN_INFO "procfs_write: write %lu bytes\n", procfs_buffer_size);
        printk(KERN_INFO "procfs_buffer = %s\n", procfs_buffer);

        imm_begin(procfs_buffer); // bridge of the process & the /proc module
        return procfs_buffer_size;
}


int procfs_open(struct inode *inode, struct file *file)
{
	try_module_get(THIS_MODULE);	// From: http://lxr.free-electrons.com/source/kernel/module.c?v=3.18#L945
	return 0;
}

int procfs_close(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);	// From: http://lxr.free-electrons.com/source/kernel/module.c?v=3.18#L964
	return 0;                /* success */
}

//static int module_permission(struct inode *inode, int op, struct nameidata *foo)
/* We allow everybody to read from our module, but
 * only root (uid 0) may write to it.
 *
 * Keep mostly read-only and often accessed (especially for
 * the RCU path lookup and 'stat' data) fields at the beginning
 * of the 'struct inode'
 * From: http://lxr.free-electrons.com/source/include/linux/fs.h?v=3.18#L538
 * struct nameidata From: http://lxr.free-electrons.com/source/include/linux/namei.h?v=3.18#L13
 */
//static int module_permission(struct inode *inode, int op)
//{
//        printk(KERN_INFO "op is %o, current euid is %u\n", op, current_euid());
//        if (op & 0x4 || (op & 0x2 && current_euid().val == (unsigned int)0))
//                return 0;

//        return -EACCES;
//}
//static struct inode_operations Inode_Ops_4_Our_Proc_File = {
//        .permission = module_permission,        // check for permissions
//};


// 定义static变量：对文件对象的操作的struct（文件对象表示进程已打开的文件）
static struct file_operations File_Ops_4_Our_Proc_File = {
        .read    = procfs_read,
        .write   = procfs_write,
        .open    = procfs_open,
        .release = procfs_close,
};


/* create and initialize the /proc file struct(struct proc_dir_entry) */
static int imm_init(void)
{
        /* 每个 proc 文件也都会用到 file_operations，在调用 create_proc_entry() 创建 proc 文件时，其中一步是调用 proc_register()，
         * proc_register() 会为 proc_dir_entry 提供一个默认的 file_operations，而 proc_create() 与 create_proc_entry() 唯一差别
         * 就是不用调用proc_register()，这样在 proc_register() 时就不会设置使用 proc_fs 默认的 file_operations 了。
         * proc_fs 默认的 file_operations 定义如下：
         *
         * static const struct file_operations proc_file_operations = {
         *      .llseek = proc_file_lseek,
         *      .read     = proc_file_read,
         *      .write     = proc_file_write,
         * };
         */

	umode_t mode = S_IFREG | S_IRUGO | S_IWUSR;
        /* create the /proc file struct(struct proc_dir_entry)*/
	Our_Proc_File = proc_create(PROC_ENTRY_FILENAME, mode, NULL, &File_Ops_4_Our_Proc_File);
	/* check if the /proc file was created successfuly */
	if (Our_Proc_File == NULL) 
	{
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
		PROC_ENTRY_FILENAME);
		return -ENOMEM;
	}
//        Our_Proc_File->proc_iops = &File_Ops_4_Our_Proc_File;

	printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);
	return 0;       /* success */
}

/* just remove the /proc file struct */
static void imm_exit(void)
{
        remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
	/* Remove a /proc entry and free it if it's not currently in use.
	 * From: http://lxr.free-electrons.com/source/fs/proc/generic.c#L544
	 */
	printk(KERN_INFO "/proc/%s removed\n", PROC_ENTRY_FILENAME);
}


module_init(imm_init);
/* Each module must use one module_init().
 * From: http://lxr.free-electrons.com/source/include/linux/init.h#L327
 */
module_exit(imm_exit); // http://blog.csdn.net/hudashi/article/details/7080071
