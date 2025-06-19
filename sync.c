/*************************************************************************** 
 * Copyright (C) 2021-2023 Derrick Greenspan and the University of Central *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * Synchronization and handling. 				   	   *
 ***************************************************************************/

#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/libnvdimm.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/libnvdimm.h>
#include <linux/perf_event.h>
#include <linux/hugetlb.h>
#include <asm/tlbflush.h>
#include <crypto/skcipher.h>
#include "../mm/internal.h"
#include "pmo.h"
#include "pagewalk.h"
#include "nopagewalk.h"

void memcpy_dirtypages(struct pmo_pages **dirty_ll, struct vpma_area_struct *vpma);


/* PSYNC */
/* systemcall */
SYSCALL_DEFINE2(psync, __u64, starting_vma_address, __u64, size)
{
        struct pmo_entry *pmo;
	
        struct vpma_area_struct *vpma;
	struct vm_area_struct *vma;
        struct mm_struct *mm;

	mm = current->mm;

	mmap_write_lock(mm);
	vma = find_vma(mm, starting_vma_address);
	mmap_write_unlock(mm);

	if(!vma->vpma) {
		printk(KERN_INFO "No associated vpma found!\n");
		return -1;
	}

	vpma = vma->vpma;
        pmo = vpma->pmo_ptr;

	if(!pmo) {
		printk(KERN_WARNING "PMO to sync is not found!\n");
		return 0;
	}

        /* Nothing to do and no cachelines to flush */
	if(!pmo_bit_is_set(1, pmo))
       		return 0;


	/* This really should not happen */
	BUG_ON(unlikely(!vpma));

         /* If the VPMA is currently in the detached state
         * (indicated by the PID INT_MIN being stored), we will refuse to psync */
        if(unlikely(vpma->calling_pid == INT_MIN))
                printk(KERN_ERR "Might not be able to sync.\n Debug: Calling PID %d,  Current PID %d, TGID %d\n",
                                vpma->calling_pid, current->pid, current->tgid);

	/* For now, we just make sure only one thread may call psync() at a
	 * time, and don't  handle memory barriers at all.*/
	mutex_lock(&vpma->psync_mutex);


	/* Indicate that we're in the process of persisting the persistent
	 * data into the shadow PMO */
	while(pmo_test_and_lock(2, pmo));
	//	printk(KERN_WARNING "Bit asserted already?");

	/* Testing something */
	pmo_sync_pages(vpma, starting_vma_address, !size); 
	//pmo_add_total_pages(vpma);

	/* Emit write barrier. By this point, all primary pages should be
	 * updated. */
	pmo_barrier(); 

	pmo_unlock_bit(3, pmo);
	pmo_unlock_bit(2, pmo);
	mutex_unlock(&vpma->psync_mutex);

        return 0;
}

void pmo_sync_pages(struct vpma_area_struct *vpma, size_t starting_vma_address, bool update_checksum)
{
	struct pmo_pages *dirty_ll = NULL;
	__maybe_unused struct mm_struct *mm = current->mm;
	__maybe_unused char sha256hash[32];
	__maybe_unused struct pmo_entry *pmo = vpma->pmo_ptr;
	__maybe_unused size_t size = pmo->size_in_pages*PAGE_SIZE,
		       psync_end = 0, psync_start = 0;

	/* STEP 1: Walk the page table or traverse all faulted pages
	 * TODO: Perhaps the dirty_ll should be built as pages are faulted in,
	 * or dirty-faulted in, rather than here. Then, the persist stage would
	 * consist of walking through (but not building) the linked list. */
	pmo_stats_start_psynctime_other(mm->pmo_stats);
	mutex_lock(&vpma->page_mutex);
	IS_ENABLED(CONFIG_PMO_PAGEWALK) ? 
		pmo_persist(vpma, starting_vma_address, &dirty_ll) :
		pmo_persist(vpma, 0, &dirty_ll);
	mutex_unlock(&vpma->page_mutex);

	/* Step 2: Persist and optionally encrypt or writeback the pages found
	 * to be dirty. */
	mutex_lock(&vpma->page_mutex);


	if(dirty_ll)
		memcpy_dirtypages(&dirty_ll, vpma);

        if(update_checksum && PMO_WHOLE_IS_ENABLED() && PMO_IV_IS_ENABLED()) {
		pmo_stats_start_psynctime_iv(current->mm->pmo_stats);
		psync_start = ktime_get_ns();
                //get_sha256_hash(sha256hash, vpma->virt_ptr, size);
                assign_sha256_to_pmo_entry(vpma->pmo_ptr, sha256hash);
                pmo_barrier();
		psync_end = ktime_get_ns();
		atomic_add(psync_end - psync_start, &current->mm->pmo_stats.psynctime_iv);
		pmo_stats_stop_psynctime_iv(current->mm->pmo_stats);
        }



	if(IS_ENABLED(CONFIG_PMO_PARANOID_MODE)) {
		pmo_destroy_shadow(vpma,vpma->faulted_pages_ll, 0);
	}
	
	kvfree(dirty_ll);
	mutex_unlock(&vpma->page_mutex);
	pmo_stats_stop_psynctime_other(mm->pmo_stats);

	return;
}

struct pmo_pages *create_dirty_ll(unsigned long int offset, struct vpma_area_struct *vpma)
{
	struct pmo_pages *dirty_ll;
	void *primary_page;

	if(offset < 0)
		return NULL;

	if (!vpma || !vpma->virt_ptr)
		return NULL;

	dirty_ll = kmalloc(sizeof(struct pmo_pages), GFP_KERNEL);
	INIT_LIST_HEAD(&dirty_ll->list);


	primary_page = vpma->virt_ptr + offset;

	pmo_do_sg_init(dirty_ll->sg_primary, primary_page);

	dirty_ll->pagenum = offset/PAGE_SIZE;

	return dirty_ll;
}


inline void pmo_clear_access(pte_t *pte)
{
	*pte = pte_mkold(*pte);
	return;
}

inline void pmo_clear_dirty(pte_t *pte)
{
	*pte = pte_mkclean(*pte);
	*pte = pte_mkold(*pte);
	return;
}


void _pmo_block_handle_sync(struct vpma_area_struct *vpma, size_t pagenum)
{
#if 0
	/* TODO: Make this crash consistent by changing metadata or the like */
	loff_t loff_primary = vpma->phys_primary + pagenum * PAGE_SIZE;
	kernel_write(PMO_FILE_PTR, vpma->primary + pagenum * PAGE_SIZE,
		       	PAGE_SIZE, &loff_primary);

//	vfs_fsync(PMO_FILE_PTR, 0);
	vfs_fsync_range(PMO_FILE_PTR, loff_primary, loff_primary + PAGE_SIZE, 0);
#endif
	return;
}

void memcpy_dirtypages(struct pmo_pages **dirty_ll, struct vpma_area_struct *vpma)
{
    struct pmo_pages *cursor, *temp;
	__maybe_unused struct mm_struct *mm = current->mm;
	__maybe_unused struct crypto_skcipher *tfm;
	__maybe_unused struct skcipher_request *req;
	__maybe_unused char local_iv[16];
	struct pmo_entry *pmo = vpma->pmo_ptr;

	if(PMO_PPs_IS_ENABLED()) {
		tfm = pmo_get_tfm(vpma);
		req = skcipher_request_alloc(tfm, GFP_KERNEL);
		memcpy(local_iv, pmo_get_iv(vpma), 16);
	}

	/* This is the first point in which the primary is being overwritten,
	 * so this is the first point where we emit a write barrier */
	pmo_barrier();

	/* This may eventually be a failure condition, but for now, we do
	 * nothing more. This really shouldn't happen, so log the condition. */
	WARN_ON(pmo_test_and_lock(3, pmo));

	/* FIXME: How can the page be destroyed if it's dirty...? */
	pmo_stats_start_psynctime_encrypt(mm->pmo_stats);
	list_for_each_entry_safe(cursor, temp, &(*dirty_ll)->list, list) {
		if(!PMO_PAGE_IS_DESTROYED(vpma, cursor->pagenum)) {
			pmo_handle_memcpy_sync(req, vpma, cursor->pagenum, local_iv,
					&cursor->sg_primary, &cursor->sg_shadow,
					(PMO_DRAM_IS_ENABLED() &&
					!PMO_DRAM_AS_BUFFER_IS_ENABLED()) ?
					&cursor->sg_working : NULL);
		}
		else {
			pmo_dec_encrypted_pages (vpma);
			/* I don't really know why this needs to be here, but
			 * apparently things break badly if it's not... */
			pmo_crypto_wakeup (vpma);
		}
	}
	pmo_barrier();

	list_for_each_entry_safe(cursor, temp, &(*dirty_ll)->list, list) {
		if (PMO_BLOCK_IS_ENABLED())
			_pmo_block_handle_sync(vpma, cursor->pagenum);

		list_del(&cursor->list);
		kfree(cursor);
	}

	pmo_stats_stop_psynctime_encrypt(mm->pmo_stats);

	pmo_psync_wait(vpma);

	if(PMO_PPs_IS_ENABLED())
		skcipher_request_free(req);

	return;
}

