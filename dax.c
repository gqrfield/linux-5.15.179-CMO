/*************************************************************************** 
 * Copyright (C) 2024 Derrick Greenspan and the University of Central      *
 * Florida (UCF).                                                          *
 ***************************************************************************
 * WARNING: THIS SOFTWARE HAS THE POTENTIAL TO DESTROY DATA.               *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY   *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or       *
 * FITNESS FOR A PARTICULAR PURPOSE.                                       *
 ***************************************************************************
 * DAX handling (i.e., Optane, CXL DAX) for PMOs			   *
 ***************************************************************************/

#include <linux/mod_devicetable.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include "pmo.h"
#include "../drivers/cxl_mem/cxl_mem_driver.h"

//extern struct cxl_mem *cxl_memPs[]; //[MAX_NRs]; //[MAX_NRs] = {NULL};
inline void dax_pmo_handle_init(void) 
{
	bool is_cxl;
	struct bar_info *cxl_bar_info;
	void *data;
	printk("Getting DAX resource for %s\n", DAX_NAME);
	if (false) { //!is_cxl) {
		printk("Not a CXL device, getting a DAX device\n");
		metadata_start = get_dax_dev_resource(DAX_NAME)->start;
		metadata_end = get_dax_dev_resource(DAX_NAME)->end;
	}
	else {
		printk("Got a CXL device...");
		cxl_bar_info = cxl_memPs[0]->bar_infoP;
		//get_cxl_mem_bar_info();
		printk("Got a CXL bar info %lX\n", cxl_bar_info);

		metadata_start = cxl_bar_info->base;
		metadata_end = cxl_bar_info->len + metadata_start;
		printk("Got a CXL device with start %lX and end %lX\n",
				metadata_start, metadata_end);

		return;
	}
	return;
}

inline void *pmo_dax_map(unsigned long int ptr, size_t size)
{
	return memremap(ptr, size, MEMREMAP_WB);
}

inline void pmo_dax_unmap(void *ptr)
{
	memunmap(ptr);
	return;
}

inline void *pmo_dax_get_header(__u64 pmo_start)
{
	return memremap(pmo_start, 4096, MEMREMAP_WB);
}

struct pmo_entry * pmo_dax_memremap(__u64 entry_id)
{
	__u64 start = metadata_start + sizeof(union pmo_header) + sizeof(__u64),
	      address;

	address = start + sizeof(struct pmo_entry) * entry_id;

	return pmo_architecture_specific_memremap(address);

}
