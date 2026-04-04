/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef KAT_OUTPUT_H
#define KAT_OUTPUT_H

/*************************************************
* Name:        generate_kat_output
*
* Description: Generate and print 5 KAT test vectors
*              to serial output in official ML-KEM format
**************************************************/
void compare_known_vector(void);
void generate_kat_output(void);
void print_hex_field(const char *name, const uint8_t *data, size_t len);

#endif // KAT_OUTPUT_H