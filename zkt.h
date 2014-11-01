#ifndef ZKT_H
# define ZKT_H

extern const	dki_t	*zkt_search (const dki_t *data, int searchtag, const char *keyname);
extern	void	zkt_list_keys (const dki_t *data);
extern	void	zkt_list_trustedkeys (const dki_t *data);
extern	void	zkt_list_dnskeys (const dki_t *data);
extern	void	zkt_setkeylifetime (dki_t *data);

#endif
