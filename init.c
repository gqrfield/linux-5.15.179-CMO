/***************************************************************************
 * Copyright (C) 2024 Derrick Greenspan and the University of Central	   *
 * Florida (UCF).							   *
 ***************************************************************************
 * Initialization handling						   *
 ***************************************************************************/
#include "pmo.h"
#include "../drivers/dax/dax-private.h"

extern unsigned long int start_of_cmo_region;
void __pmo_handle_init(void)
{
	if (PMO_DAX_IS_ENABLED())
		dax_pmo_handle_init();
	else
		block_pmo_handle_init();
	return;
}


bool init_mapping(union pmo_header *header)
{
	  printk("Strncmp on header %lX\n", header);
          strncpy((char *)header, "CMO\0", 4);
	  printk("Got header %lX\n", header);
          if(strncmp((char *) header, "CMO", 3) != 0) {
		  printk("%s\n", header);
                  return false;
	  }
	  
	  printk("2: Got header %lX\n", header);
          return true;
}

/* Get the PMO Header region. */
union pmo_header *_pmo_header_get(__u64 pmo_start, __u64 pmo_end)
{
          /* Get header region */
          union pmo_header * header = PMO_DAX_IS_ENABLED() ?
		  pmo_dax_get_header(pmo_start):
		  pmo_block_get_header(pmo_start);
  
          if(!header)
                  goto err_no_mapping;
          else if(strncmp((char *) header, "CMO\0", 4) != 0) {
		  if(init_mapping(header))
			  return header;
                  goto no_header;
	  }
          else {
		  printk("Got header %lX\n", header);
                  return header;
	  }
  
          no_header:
	  	printk(KERN_WARNING "No CMO header exists!\n");
		return ERR_PTR(-ENOENT);
  
          err_no_mapping:
                  printk(KERN_ERR "Could not map 0x%llx!\n", pmo_start);
                  return ERR_PTR(-EFAULT);
}



void pmo_handle_init(bool init_proc) 
{
	pmo_area_cachep = KMEM_CACHE(vpma_area_struct, SLAB_PANIC|SLAB_ACCOUNT);
	
	printk("hello world i am owen");

	if (init_proc)
		pmo_proc_init();

	printk("pmo_area_cachep is %llX\n",
			(long long unsigned int) pmo_area_cachep);

	
	/* If using DAX, this will be get_dev_dax_resource(DAX_NAME)->start/end
	 * Otherwise this will just be 0 and the end of the block device */ 
	__pmo_handle_init();

	printk("We got the metadata start %lX\n", metadata_start);
	header = _pmo_header_get(metadata_start, metadata_end);
	printk("Got header %lX\nHeader says: %s\n", header, header);

	init_sha256_region(metadata_start, metadata_end);

	mutex_init(&pmo_system_mutex);
	atomic_inc(&header->this.boot_id);
	pmo_update_header();

	memset(ZEROED_PAGE, 0x00, PAGE_SIZE);
	pmo_initialize_checksum();
	pmo_print_config();
	start_of_cmo_region = header->this.next_free_pmo;

	return;
}

struct sha256_pages *initialize_sha256_list(void)
{
        char sanity[32];
        int i;
        struct sha256_pages *sha256_list =  NULL;
		

         for(i = 0; i < (0x4000000); i++) {
                memcpy(sha256_list->page_hash[i].sum, sanity, 32);
                WARN_ON(memcmp(sanity, sha256_list->page_hash[i].sum, 32) != 0);
         }

         return sha256_list;
}

void initialize_cmo_subsystem(void *data, size_t len, __u64 start, __u64 end)
{
	int i;
	union pmo_header *local_cmo_header = 
		(union pmo_header*) data;
	union pmo_nodelist *nodelist =  
		((void *) ((union pmo_nodelist *) data)) + sizeof(union pmo_header);
	struct sha256_pages *pages = initialize_sha256_list();


	BUG_ON(!local_cmo_header);
	strcpy((char *)local_cmo_header, "CMO\0");
	strcpy(local_cmo_header->this.name, "Test_CMO\n");

	local_cmo_header->this.pmo_range.start = start;
	local_cmo_header->this.pmo_range.end = end;
	local_cmo_header->this.nodelist_location = sizeof(union pmo_header);
	local_cmo_header->this.sha256_region_location = 
		sizeof(union pmo_header) + sizeof(union pmo_nodelist);

	BUG_ON(sizeof(struct sha256_pages) != 2147483648);

	/* The next free CMO is initially the size of the database + 
	 * sizeof(region_location) + sizeof(nodelist) */

	local_cmo_header->this.next_free_pmo = sizeof(union pmo_header) +
		sizeof(union pmo_nodelist) + sizeof(struct sha256_pages);

	local_cmo_header->this.pmo_region_location =
		local_cmo_header->this.next_free_pmo;

	printk(KERN_INFO "Next Free CMO is %llX\n",
			local_cmo_header->this.next_free_pmo);

	printk("Copying %lX, size %lX, end %lX\n",
			data + sizeof(union pmo_header),
			sizeof(union pmo_nodelist),
			data + sizeof(union pmo_nodelist) + sizeof(union pmo_header));


	memcpy(data + sizeof(union pmo_header) + sizeof(union pmo_nodelist),
			pages, sizeof(struct sha256_pages));
	printk("copied sha256 pages\n");

	printk("Union pmo nodelist is %lX\n", sizeof(union pmo_nodelist));

	for (i = 0; i < 2000000; i++)
		memset(&nodelist->this.nodes[i].name, 0, 20); //sizeof(union pmo_nodelist)/64);
	printk("set nodelist\n");

	return;
	
}
