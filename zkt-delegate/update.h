#ifndef UPDATE_H
# define UPDATE_H

extern	ldns_rr_list	*prepare_ns_update (const char *origin, uint32_t ttl, int argc, char **argv);
extern	ldns_rr_list	*prepare_ds_update (const char *dname, uint32_t ttl, ldns_rr_list **ppr_rrlist, int argc, char **argv);
extern	ldns_rr_list	*prepare_glue_update (const char *origin, uint32_t ttl, ldns_rr_list **ppr_rrlist, int argc, char **argv);
extern	int	sendupdate (ldns_resolver *res, ldns_rdf *zone_rdf, ldns_rr_list *pr_rrlist, ldns_rr_list *up_rrlist, ldns_rr_list *ad_rrlist, ldns_tsig_credentials *tsig_cred);
#endif
