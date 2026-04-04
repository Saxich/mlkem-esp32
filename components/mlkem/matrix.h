/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef matrix_H
#define matrix_H

#if defined(SPEED_DUALCORE)
        //matrix gen macros
        #if MLKEM_K == 2
            //4 elemnts 0-3
            #define CORE0_START_ELEMENT 0
            #define CORE0_END_ELEMENT   1    
            #define CORE1_START_ELEMENT 2     
            #define CORE1_END_ELEMENT   3
        #elif MLKEM_K == 3
            //9 elemnts 0-8
            #define CORE0_START_ELEMENT 0
            #define CORE0_END_ELEMENT   3   
            #define CORE1_START_ELEMENT 4 
            #define CORE1_END_ELEMENT   8 
        #elif MLKEM_K == 4
            //16 elemnts 0-15
            #define CORE0_START_ELEMENT 0
            #define CORE0_END_ELEMENT   7        
            #define CORE1_START_ELEMENT 8
            #define CORE1_END_ELEMENT   15 
        #endif  

        //matrix vector multiplication macros
        #if MLKEM_K == 2
            //0-1
            #define CORE0_MVM_START 0
            #define CORE0_MVM_END   0   
            #define CORE1_MVM_START 1   
            #define CORE1_MVM_END   1
        #elif MLKEM_K == 3
            //0-2
            #define CORE0_MVM_START 0
            #define CORE0_MVM_END   1 
            #define CORE1_MVM_START 2 
            #define CORE1_MVM_END   2  
        #elif MLKEM_K == 4
            //0-3
            #define CORE0_MVM_START 0
            #define CORE0_MVM_END   1
            #define CORE1_MVM_START 2  
            #define CORE1_MVM_END   3 
        #endif 
#elif defined(SPEED)
        //matrix gen macros
        #if MLKEM_K == 2
            //4 elemnts 0-3
            #define SC_MATRX_STRT_EL 0
            #define SC_MATRX_END_EL   3   
        #elif MLKEM_K == 3
            //9 elemnts 0-8
            #define SC_MATRX_STRT_EL 0
            #define SC_MATRX_END_EL   8  
        #elif MLKEM_K == 4
            //16 elemnts 0-15
            #define SC_MATRX_STRT_EL 0
            #define SC_MATRX_END_EL   15       
        #endif  

#endif //DUALCORE matrix macros

#ifdef STACK_CODE

    #include "params.h"

    #define matacc MLKEM_NAMESPACE(matacc)
    void matacc(poly *r, const polyvec *b, unsigned char i, const unsigned char *seed, int transposed);

    void matacc_opt(poly *r, const poly *v, poly *mag, unsigned char i, const unsigned char *seed, const unsigned char *coins, int transposed);

    void matacc_xtreme(poly *r, poly *mag, unsigned char i, const unsigned char *seed, const unsigned char *coins, int transposed);

#endif //(STACK_CODE)


#ifdef SPEED_CODE

    #define gen_a_elements(a, b, c, d)   gen_matrix_elements(a, b, c, d, 0)

    #define gen_at_elements(a, b, c, d)  gen_matrix_elements(a, b, c, d, 1)

    void gen_matrix_elements(polyvec *a, const uint8_t seed[MLKEM_SYMBYTES],
                             int start_element, int stop_element, int transposed);

#endif //(SPEED_CODE)



#endif
