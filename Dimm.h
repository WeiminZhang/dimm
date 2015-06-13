/* DIMM : Dynamic Integrity Measurement Module */

#include <linux/init.h>
#include <linux/module.h>	// Dynamic loading of modules into the kernel
#include <linux/crypto.h>	// Scatterlist Cryptographic API.
#include <linux/scatterlist.h>  // sg table
#include <linux/security.h>	// Linux Security plug
#include <linux/hash.h>		// Fast hashing routine for ints,  longs and pointers
#include <linux/kernel.h> 
#include <linux/string.h>
#include <linux/sched.h>	// Extended scheduling parameters data structure
                                // (The definition of task_struct is in it)
#include <linux/profile.h>	// Basic kernel profiler (分析器)
#include <linux/mm.h>		// Linux kernel virtual "memory manager" primitives
#include <linux/kernel_stat.h>  // contains the definitions needed for doing some kernel statistics
                                // (CPU usage, context switches ...), used by rstatd/perfmeter.
#include <linux/hugetlb.h>      // Hugepages at page global directory.
                                // If arch support hugepages at pgd level, they need to define this.
#include <linux/mman.h>		// Allow architectures to handle additional protection bits
#include <linux/swap.h>		// A swap extent maps a range of a swapfile's PAGE_SIZE pages onto a range of disk blocks.
                                // A list of swap extents maps the entire swapfile.
#include <linux/highmem.h>	// About high memory
#include <linux/pagemap.h>	// The page cache can be done in larger chunks than one page,
                                // because it allows for more efficient throughput
                                // (it can then be mapped into user space in smaller chunks for same flexibility).
                                // Or rather, it _will_ be done in larger chunks.
#include <linux/rmap.h>		// Declarations for Reverse Mapping functions in mm/rmap.c.
#include <asm/uaccess.h>        // User space memory access functions,
                                // these should work on any machine that has kernel
                                // and user data in the same address space, e.g. all NOMMU machines.
#include <asm/tlb.h>		// Generic TLB shootdown code
#include <asm/tlbflush.h>       // This is a dummy tlbflush implementation that can be used on all nommu architectures.
                                // If you have an MMU, you need to write your own functions.
#include <asm/pgtable.h>        // On almost all architectures and configurations,
                                // 0 can be used as the upper ceiling to free_pgtables():
                                // on many architectures it has the same effect as using TASK_SIZE.
                                // However, there is one configuration which must impose a more careful limit,
                                // to avoid freeing kernel pgtables.
#include <linux/swapops.h>      // Swapcache pages are stored in the swapper_space radix tree.
                                // We want to get good packing density in that tree,
                                // so the index should be dense in the low-order bits.
#include <linux/proc_fs.h>	// The proc filesystem constants/structures
#include <linux/timex.h>
#include <linux/rtc.h>		// Generic RTC interface. Real-Time Clock
#include <linux/tpm.h>          // Device driver for TCG/TCPA TPM (trusted platform module).
                                // Specifications at www.trustedcomputinggroup.org
//#include <linux/time.h>
//#include <linux/timex.h>
//#include <linux/rtc.h>
//#include <linux/timer.h>

/* TODO: How to use GPL License!? */
//MODULE_AUTHOR("Ruins"); Original Code Author
MODULE_AUTHOR("ice.he.hzy@gmail.com"); // Improved Code Author
MODULE_LICENSE("GPL");

#define DEBUG 1
#define PROC_ENTRY_FILENAME "dynamic_measurement"	// 运行入口的文件名
#define PROCFS_MAX_SIZE 1024	// 进程文件系统最大大小 (PROCFS - PROCessFileSystem 进程文件系统)

/* 用户空间与内核空间交互的数据结构（通过读写/proc文件）*/
struct measurement_member{
    char target_name[256];
    char target_hash[41];
    char argv[256];
    char argv_hash[41];
    char time_stamp[40];
}measurement_output;

/* 日历时间 */
struct caltime {
    time_t nowsec;
    time_t nowmin;
    time_t nowh;
    time_t nowd;
    time_t nowm;
    time_t nowy;
};

static char procfs_buffer[PROCFS_MAX_SIZE];  // （进程文件系统buffer） 内核空间buffer
static unsigned long procfs_buffer_size = 0;
static struct proc_dir_entry *Our_Proc_File; // （进程目录入口） 内核模块对应的/proc目录项

int imm_begin(char *);

/* task_struct
 * PCB - Process Control Block 进程控制块的结构
 * From: http://lxr.free-electrons.com/source/include/linux/sched.h?v=3.18#L280	Line 1235 - 1664
 */

/* read the target target' userspace 读取目标的用户空间 */
int read_process_space(struct task_struct *, unsigned long , char *, int , int );

/* get the content to be hashed	获得需要被哈希的内容 */
int get_hash_content(struct task_struct *, unsigned long , char *, int );

/* compute the process's hash 计算目标的哈希值 */
int compute_p_hash(struct task_struct *, unsigned long , size_t , int );  //对process进行hash

/* get time_stamp 获得时间戳 */
int get_timestamp(void);

/* measure */
int do_code_hash(char* );
