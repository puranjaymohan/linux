/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright 2019-2020 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef _EFA_GDR_H_
#define _EFA_GDR_H_

#include "efa.h"
#include "nv-p2p.h"

struct efa_nvmem {
	struct efa_dev *dev;
	struct nvidia_p2p_page_table *pgtbl;
	struct nvidia_p2p_dma_mapping *dma_mapping;
	u64 virt_start;
	u64 ticket;
	u32 lkey;
	bool needs_dereg;
	struct list_head list; /* member of nvmem_list */
};

void nvmem_init(void);
struct efa_nvmem *nvmem_get(struct efa_dev *dev, struct efa_mr *mr, u64 start,
			    u64 length, unsigned int *pgsz);
int nvmem_to_page_list(struct efa_dev *dev, struct efa_nvmem *nvmem,
		       u64 *page_list);
int nvmem_put(u64 ticket, bool in_cb);
void nvmem_release(struct efa_dev *dev, struct efa_nvmem *nvmem, bool in_cb);

#endif /* _EFA_GDR_H_ */
