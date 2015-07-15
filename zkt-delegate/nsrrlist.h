#ifndef NSRRLIST_h
# define NSRRLIST_h
extern	ldns_rr_list	*zone_ns_rr_list (const ldns_zone *z, ldns_rr_list **pglue_rr_list);
extern	ldns_rr_list	*zone_ds_rr_list (const ldns_zone *z, int use_cds);
#endif
