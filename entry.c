/***************************************************************************
 * Copyright (C) 2023 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).							   *
 ***************************************************************************
 * attach/detach/alloc handling, as all comes from attach syscall	   *
 ***************************************************************************/

#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include "../drivers/nvme/host/nvme.h"
#include "pmo.h"


struct proc_dir_entry *pmo_proc_entry, *pmo_dram_entry, *pmo_pred_entry, *pmo_depth_entry,
		      *pmo_debug_entry, *pmo_access_entry, *pmo_emulate_cxl_entry = PMO_LOCAL;
enum access_type pmo_access_mode = DAX;
SYSCALL_DEFINE6(attach, char __user *, path, unsigned, access_type, char __user *, key,
	       	__u64, size, __u64, offset, __u64 __user *, return_data)
{
	__u64 address, aligned_size, page_offset;
        char path_buf[256],
	     key_buf[256],
	     name[256];

        long copied_path, copied_key;
	struct pmo_entry *pmo;

	struct mm_struct *mm = current->mm;

	if(pmo_area_cachep == NULL)  
		pmo_handle_init(true);


	/* detach */
	if(access_type == 'd' || access_type == 'D' || access_type == 'n') {
		do_detach(mm, path);
		return 0;
	}
	if(access_type == 's')
		return do_get_size(mm, path);

        copied_path = strncpy_from_user(name, path, sizeof(path_buf));
	if(unlikely(!copied_path))  {
		printk(KERN_ERR "Error: No such path copied\n");
		return -ENOENT;
	}

	pmo = radix_tree_lookup(&pmo_radix_tree,djb2_hash(name));

	if(!pmo) 
		pmo = get_pmo_from_name(name);

	/* exists -- check whether the PMO exists */
	if(access_type == 'e')
		return (pmo != 0);


	copied_key = strncpy_from_user(key_buf, key, sizeof(key_buf));

	/* Create
	 *
	 * Note: the proper behavior when a PMO already exists and a creation
	 * request occurs is to return -ENOENT, because the PMO already exists.
	 * However, for benchmarking, we need to first create or append a PMO
	 * and we'll need to do this many times. Since we can't delete PMOs
	 * right now, we'll just recreate the PMO for now, creating a memory 
	 * leak.
	 */
	if(access_type == 'c' || access_type == 'C') {
		/* Pass in the key which, along with the IV, will be forged to the
		 * PMO. The PMO is initially empty. */
		printk("Trying to create PMO %s of size %lld\n", name, size);

		pmo_stats_start_create_time(mm->pmo_stats);
		do_create(name, size, key_buf);
		pmo_stats_stop_create_time(mm->pmo_stats);
		return 0;
	}


	if(unlikely(!pmo)) {
		printk(KERN_ERR "PMO %s not found.\n", name);
		return -ENOENT;
	}

	/* If not page aligned, this is bad so dump to kernel log */
	WARN(!PAGE_ALIGNED(offset), "Offset %ld ! page aligned!\n", (size_t) offset);

	aligned_size = PAGE_ALIGN(size);
	page_offset = offset / PAGE_SIZE;

	mmap_read_lock(mm);
	address = (__u64) do_attach(pmo, access_type, aligned_size,
			page_offset, key_buf);
	mmap_read_unlock(mm);


	if(!address)
		do_exit(SIGBUS);

	put_user(address, return_data);

	return 0;
}

void pmo_print_config(void) 
{

	char mode[30];
	pmo_get_mode(mode);

	printk(KERN_INFO "Current PMO configuration is %s\n", mode);
	
	return;
}

void _pmo_memcpy_sync(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow,
		struct scatterlist *sg_working)
{
	/* Handle this memcpy in a special way for a block device. */
	if (PMO_DRAM_IS_ENABLED()) {
		PMO_DRAM_AS_BUFFER_IS_ENABLED() ? 
			pmo_handle_memcpy_sync_shadow_only(req, vpma, pagenum,
					local_iv, sg_primary, sg_shadow):
			PMO_NOENC_IS_ENABLED() ? 
				pmo_handle_memcpy_sync_noenc(req, vpma, pagenum,
					local_iv, sg_primary, sg_shadow):
				pmo_handle_memcpy_sync_dram(req, vpma, pagenum,
					local_iv, sg_primary, sg_working);
		return;
	}

	/* NOENC, PPs, PPb, WHOLE, PPsIVd, PPbIVd, PPsIVp, PPbIVp, WHOLEIV */
	if (PMO_NOENC_IS_ENABLED()) {
		pmo_handle_memcpy_sync_noenc(req, vpma, pagenum,
				local_iv, sg_primary, sg_shadow);
		return;
	}

	if (PMO_PPs_IS_ENABLED()) {
		pmo_handle_memcpy_sync_shadow_only(req, vpma, pagenum,
				local_iv, sg_primary, sg_shadow);
		return;
	}

	return;
}

void pmo_handle_memcpy_sync(struct skcipher_request *req,
		struct vpma_area_struct *vpma, size_t pagenum, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_shadow,
		struct scatterlist *sg_working)
{
	__maybe_unused loff_t primary_pos; 

	_pmo_memcpy_sync(req, vpma, pagenum, local_iv, sg_primary,
				sg_shadow, sg_working);

	if (PMO_DAX_IS_ENABLED())
		return;

#if 0
	primary_pos = (loff_t) (vpma->phys_primary + pagenum * PAGE_SIZE);
	kernel_write(PMO_FILE_PTR, vpma->shadow + pagenum * PAGE_SIZE,
			       	PAGE_SIZE, &primary_pos);
#endif
	return;
}


void pmo_psync_wait(struct vpma_area_struct *vpma) 
{
	if (PMO_PPs_IS_ENABLED())
		wait_event(vpma->crypto.encrypt_wq,
				!atomic_read(&vpma->crypto.encrypted_pages));
	return;
}

void pmo_fault_wait(struct pmo_pages *sentinel)
{
	if (PMO_DRAM_IS_ENABLED())
		wait_event(sentinel->wq, !atomic_read(&sentinel->pagecount));
}


void pmo_init_pred_working_data (struct vpma_area_struct *vpma, unsigned long pagenum)
{                 
 
	PMO_DRAM_IS_ENABLED() ? pmo_init_dram_working_data(vpma, pagenum) :
		pmo_init_pmem_working_data(vpma, pagenum);

	sg_init_one(&vpma->working_data[pagenum].sg_primary,
			vpma->virt_ptr + pagenum * PAGE_SIZE, PAGE_SIZE);
	return;
}

void pmo_handle_page_prediction_enc(struct skcipher_request *req,
		struct vpma_area_struct *vpma, char *local_iv,
		struct scatterlist *sg_primary, struct scatterlist *sg_other,
		unsigned long int pagenum)
{
	PMO_DRAM_IS_ENABLED() ?
		_pmo_handle_page_dram_crypto_prediction(req, vpma, local_iv,
				sg_primary, sg_other, pagenum) :
		_pmo_handle_page_pmem_prediction(req, vpma, local_iv,
				sg_primary, sg_other, pagenum);
	return;
}

void _pmo_handle_page(struct vpma_area_struct *vpma, unsigned long int pagenum)
{

	if (PMO_DRAM_IS_ENABLED())  
		pmo_handle_page_dram(vpma, pagenum * PAGE_SIZE);

	else if(PMO_NOENC_IS_ENABLED()) 
		pmo_handle_page_noenc(vpma, pagenum * PAGE_SIZE);

	else if(PMO_PPs_IS_ENABLED()) 
		pmo_handle_page_shadow(vpma, pagenum * PAGE_SIZE);


	return;
}

void pmo_handle_page(struct vpma_area_struct *vpma, unsigned long int pagenum)
{
	if (!PMO_WHOLE_IS_ENABLED()) 
		pmo_insert_faulted_pages(vpma, pagenum * PAGE_SIZE);

	_pmo_handle_page(vpma, pagenum);

	return;

}

inline void *pmo_map(unsigned long int ptr, size_t size)
{
	return PMO_DAX_IS_ENABLED() ? pmo_dax_map(ptr, size) : 
		pmo_block_map(ptr, size);
}

inline void cmo_unmap(char *name) 
{
	printk("Unmapping %s\n", name);
	cmo_recycle(djb2_hash(name));
//	PMO_DAX_IS_ENABLED() ? pmo_dax_unmap(ptr) : pmo_block_unmap(ptr);
	return;
}

bool warned = false;
inline void pmo_sync (void *address, size_t size)
{
	if (PMO_DAX_IS_ENABLED()) {
		if (!warned) {
			printk(KERN_WARNING "The system does not support arch_wb_cache_pmem at this time\n");
			warned = true;
		}
		return;
	       	arch_wb_cache_pmem(address, size);
	}
	else
		vfs_fsync(PMO_FILE_PTR, 0);
	return;
}

inline void pmo_barrier(void)//struct pmo_pages_ll *pages_ll)
{
	struct nvme_ctrl *ctrl;

	/* The barrier, if we are not using DAX, occurrs at sync. */
	if(PMO_DAX_IS_ENABLED()) 
		pmem_wmb();
	else {/* FIXME, this should have an additional argument or something... */
		ctrl = container_of(PMO_DEV_PTR, struct nvme_ctrl, ctrl_device);
		/* TODO:
		 * We want this sync to issue to the NVMe controller so that it
		 * tells the controller precisely which blocks need to be
		 * flushed (later, remapped). This request will need to be 
		 * issued after all others have completed, so it helps to treat
		 * it as if it were a normal flush request 
		vfs_fsync(PMO_FILE_PTR, 0);
		*/
	}
	return;
}

inline void pmo_update_metadata(struct vpma_area_struct *vpma)
{
	if(PMO_BLOCK_IS_ENABLED()) 
		pmo_block_update_metadata(vpma);
	return;
}
void pmo_update_header(void)
{
	if(PMO_BLOCK_IS_ENABLED())
		pmo_block_update_header();
	return;
}

