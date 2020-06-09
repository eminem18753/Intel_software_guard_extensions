#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t generate_random_number(sgx_enclave_id_t eid, int* retval);
sgx_status_t train_logistic_regression1(sgx_enclave_id_t eid, float* data, int* labels, float lr, int iter, unsigned int data_rows, unsigned int data_cols, unsigned int data_len, float* weights);
sgx_status_t init_logistic_enclave(sgx_enclave_id_t eid);
sgx_status_t get_public_key_length(sgx_enclave_id_t eid, int* retval);
sgx_status_t decrypt(sgx_enclave_id_t eid, int data_len, unsigned char* encrypted_data, unsigned char* decrypted);
sgx_status_t get_public_key(sgx_enclave_id_t eid, unsigned char* ptr, int len);
sgx_status_t destroy_logistic_enclave(sgx_enclave_id_t eid);
sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
