/**
 * \file bignum.h
 *
 * \brief This file defines the Mbed TLS multi-precision integer library.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved.
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_BIGNUM_H
#define MBEDTLS_BIGNUM_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#endif

#define MBEDTLS_ERR_MPI_FILE_IO_ERROR                     -0x0002  /**< An error occurred while reading from or writing to a file. */
#define MBEDTLS_ERR_MPI_BAD_INPUT_DATA                    -0x0004  /**< Bad input parameters provided to the function. */
#define MBEDTLS_ERR_MPI_INVALID_CHARACTER                 -0x0006  /**< There is an invalid character in the digit string. */
#define MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL                  -0x0008  /**< The buffer is too small to write to. */
#define MBEDTLS_ERR_MPI_NEGATIVE_VALUE                    -0x000A  /**< The input arguments are negative or result in illegal output. */
#define MBEDTLS_ERR_MPI_DIVISION_BY_ZERO                  -0x000C  /**< The input argument for division is zero, which is not allowed. */
#define MBEDTLS_ERR_MPI_NOT_ACCEPTABLE                    -0x000E  /**< The input arguments are not acceptable. */
#define MBEDTLS_ERR_MPI_ALLOC_FAILED                      -0x0010  /**< Memory allocation failed. */

#define MBEDTLS_MPI_CHK(f) do { if( ( ret = f ) != 0 ) goto cleanup; } while( 0 )

/*
 * Maximum size MPIs are allowed to grow to in number of limbs.
 */
#define MBEDTLS_MPI_MAX_LIMBS                             10000

#if !defined(MBEDTLS_MPI_WINDOW_SIZE)
/*
 * Maximum window size used for modular exponentiation. Default: 6
 * Minimum value: 1. Maximum value: 6.
 *
 * Result is an array of ( 2 << MBEDTLS_MPI_WINDOW_SIZE ) MPIs used
 * for the sliding window calculation. (So 64 by default)
 *
 * Reduction in size, reduces speed.
 */
#define MBEDTLS_MPI_WINDOW_SIZE                           6        /**< The maximal window-size used. */
#endif /* !MBEDTLS_MPI_WINDOW_SIZE */

#if !defined(MBEDTLS_MPI_MAX_SIZE)
/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * ( Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits )
 *
 * Note: Calculations can temporarily result in larger MPIs. So the number
 * of limbs required (MBEDTLS_MPI_MAX_LIMBS) is higher.
 */
#define MBEDTLS_MPI_MAX_SIZE                              1024     /**< The maximal number of bytes for usable MPIs. */
#endif /* !MBEDTLS_MPI_MAX_SIZE */

#define MBEDTLS_MPI_MAX_BITS                              ( 8 * MBEDTLS_MPI_MAX_SIZE )    /**< The maximal number of bits for usable MPIs. */

/*
 * When reading from files with mbedtls_mpi_read_file() and writing to files with
 * mbedtls_mpi_write_file() the buffer should have space
 * for a (short) label, the MPI (in the provided radix), the newline
 * characters and the '\0'.
 *
 * By default we assume at least a 10 char label, a minimum radix of 10
 * (decimal) and a maximum of 4096 bit numbers (1234 decimal chars).
 * Autosized at compile time for at least a 10 char label, a minimum radix
 * of 10 (decimal) for a number of MBEDTLS_MPI_MAX_BITS size.
 *
 * This used to be statically sized to 1250 for a maximum of 4096 bit
 * numbers (1234 decimal chars).
 *
 * Calculate using the formula:
 *  MBEDTLS_MPI_RW_BUFFER_SIZE = ceil(MBEDTLS_MPI_MAX_BITS / ln(10) * ln(2)) +
 *                                LabelSize + 6
 */
#define MBEDTLS_MPI_MAX_BITS_SCALE100          ( 100 * MBEDTLS_MPI_MAX_BITS ) /**< The number of maximum bits scaled up by 100. */
#define MBEDTLS_LN_2_DIV_LN_10_SCALE100                 332 /**< The natural base logarithm of 2 divided by the natural base logarithm of 10, and scaled up by 100. */
#define MBEDTLS_MPI_RW_BUFFER_SIZE             ( ((MBEDTLS_MPI_MAX_BITS_SCALE100 + MBEDTLS_LN_2_DIV_LN_10_SCALE100 - 1) / MBEDTLS_LN_2_DIV_LN_10_SCALE100) + 10 + 6 ) /**<  The MPI buffer size. */

/*
 * Define the base integer type, architecture-wise.
 *
 * 32 or 64-bit integer types can be forced regardless of the underlying
 * architecture by defining MBEDTLS_HAVE_INT32 or MBEDTLS_HAVE_INT64
 * respectively and undefining MBEDTLS_HAVE_ASM.
 *
 * Double-width integers (e.g. 128-bit in 64-bit architectures) can be
 * disabled by defining MBEDTLS_NO_UDBL_DIVISION.
 */
#if !defined(MBEDTLS_HAVE_INT32)
    #if defined(_MSC_VER) && defined(_M_AMD64)
        /* Always choose 64-bit when using MSC */
        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif /* !MBEDTLS_HAVE_INT64 */
        typedef  int64_t mbedtls_mpi_sint;
        typedef uint64_t mbedtls_mpi_uint;
    #elif defined(__GNUC__) && (                         \
        defined(__amd64__) || defined(__x86_64__)     || \
        defined(__ppc64__) || defined(__powerpc64__)  || \
        defined(__ia64__)  || defined(__alpha__)      || \
        ( defined(__sparc__) && defined(__arch64__) ) || \
        defined(__s390x__) || defined(__mips64) )
        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif /* MBEDTLS_HAVE_INT64 */
        typedef  int64_t mbedtls_mpi_sint;
        typedef uint64_t mbedtls_mpi_uint;
        #if !defined(MBEDTLS_NO_UDBL_DIVISION)
            /* mbedtls_t_udbl defined as 128-bit unsigned int */
            typedef unsigned int mbedtls_t_udbl __attribute__((mode(TI)));
            #define MBEDTLS_HAVE_UDBL
        #endif /* !MBEDTLS_NO_UDBL_DIVISION */
    #elif defined(__ARMCC_VERSION) && defined(__aarch64__)
        /*
         * __ARMCC_VERSION is defined for both armcc and armclang and
         * __aarch64__ is only defined by armclang when compiling 64-bit code
         */
        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif /* !MBEDTLS_HAVE_INT64 */
        typedef  int64_t mbedtls_mpi_sint;
        typedef uint64_t mbedtls_mpi_uint;
        #if !defined(MBEDTLS_NO_UDBL_DIVISION)
            /* mbedtls_t_udbl defined as 128-bit unsigned int */
            typedef __uint128_t mbedtls_t_udbl;
            #define MBEDTLS_HAVE_UDBL
        #endif /* !MBEDTLS_NO_UDBL_DIVISION */
    #elif defined(MBEDTLS_HAVE_INT64)
        /* Force 64-bit integers with unknown compiler */
        typedef  int64_t mbedtls_mpi_sint;
        typedef uint64_t mbedtls_mpi_uint;
    #endif
#endif /* !MBEDTLS_HAVE_INT32 */

#if !defined(MBEDTLS_HAVE_INT64)
    /* Default to 32-bit compilation */
    #if !defined(MBEDTLS_HAVE_INT32)
        #define MBEDTLS_HAVE_INT32
    #endif /* !MBEDTLS_HAVE_INT32 */
    typedef  int32_t mbedtls_mpi_sint;
    typedef uint32_t mbedtls_mpi_uint;
    #if !defined(MBEDTLS_NO_UDBL_DIVISION)
        typedef uint64_t mbedtls_t_udbl;
        #define MBEDTLS_HAVE_UDBL
    #endif /* !MBEDTLS_NO_UDBL_DIVISION */
#endif /* !MBEDTLS_HAVE_INT64 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The MPI structure.
 */
typedef struct
{
    int s;                  /*!< The integer sign. */
    size_t n;               /*!< The total number of limbs. */
    mbedtls_mpi_uint *p;    /*!< A pointer to the limbs. */
}
mbedtls_mpi;

/**
 * \brief           This function initializes a single MPI (makes internal
 *                  references valid).
 *
 *                  This prepares the MPI to be set or freed,
 *                  but does not define a value for the MPI.
 *
 * \param X         The MPI to initialize.
 */
void mbedtls_mpi_init( mbedtls_mpi *X );

/**
 * \brief          This function unallocates a single MPI.
 *
 * \param X        The MPI to unallocate.
 */
void mbedtls_mpi_free( mbedtls_mpi *X );

/**
 * \brief          This function enlarges to the specified number of limbs.
 *
 * \note           This function does nothing if the MPI is already large
 *                 enough.
 *
 * \param X        The MPI to enlarge.
 * \param nblimbs  The target number of limbs.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_grow( mbedtls_mpi *X, size_t nblimbs );

/**
 * \brief          This function resizes down, keeping at least the
 *                 number of limbs specified in \p nblimbs.
 *
 *                 If \p X is smaller than \p nblimbs, it is resized up
 *                 instead.
 *
 * \param X        The MPI to shrink.
 * \param nblimbs  The minimum number of limbs to keep.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 *                 This can only happen when resizing up.
 */
int mbedtls_mpi_shrink( mbedtls_mpi *X, size_t nblimbs );

/**
 * \brief          This function copies the contents of \p Y into \p X.
 *
 * \param X        The MPI to copy the contents to. It is enlarged if necessary.
 * \param Y        The MPI to copy the contents from.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_copy( mbedtls_mpi *X, const mbedtls_mpi *Y );

/**
 * \brief          This function swaps the contents of \p X and \p Y.
 *
 * \param X        The first MPI value.
 * \param Y        The second MPI value.
 */
void mbedtls_mpi_swap( mbedtls_mpi *X, mbedtls_mpi *Y );

/**
 * \brief          This function assigns the value of \p Y to \p X,
 *                 if \p assign is \c 1. If \p assign is \c 0, the
 *                 value is not assigned.
 *
 * \note           This function is equivalent to
 *                 <code>if( assign ) mbedtls_mpi_copy( X, Y );</code>,
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not. The above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis.
 *
 * \param X        The MPI to conditionally assign to.
 * \param Y        The value to be assigned.
 * \param assign   \c 1: perform the assignment, or \c 0: keep the original
 *                 value of \p X.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_safe_cond_assign( mbedtls_mpi *X, const mbedtls_mpi *Y, unsigned char assign );

/**
 * \brief          This function swaps the value of \p X with the value of
 *                 \p X, if \p assign is \c 1. If \p assign is \c 0, the
 *                 values are not assigned.
 *
 * \note           This function is equivalent to
 *                 <code>if( assign ) mbedtls_mpi_swap( X, Y );</code>
 *                 except that it avoids leaking any information about whether
 *                 the assignment was done or not. The above code may leak
 *                 information through branch prediction and/or memory access
 *                 patterns analysis.
 *
 * \param X        The first value to swap.
 * \param Y        The second value to swap.
 * \param assign   \c 1: perform the swap, or \c 0: keep the original values of
 *                 \p X and \p Y.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_safe_cond_swap( mbedtls_mpi *X, mbedtls_mpi *Y, unsigned char assign );

/**
 * \brief          This function sets a value to \p X from an integer in \p z.
 *
 * \param X        The MPI to set.
 * \param z        The value to use.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_lset( mbedtls_mpi *X, mbedtls_mpi_sint z );

/**
 * \brief          This function receives a specific bit from \p X.
 *
 * \param X        The MPI to use.
 * \param pos      The zero-based index of the bit in \p X.
 *
 * \return         Either a \c 0 or a \c 1.
 */
int mbedtls_mpi_get_bit( const mbedtls_mpi *X, size_t pos );

/**
 * \brief          This function sets a bit of \p X to either \c 0 or \c 1.
 *
 * \note           The function will enlarge \p X, if necessary, to set a bit to
 *                 \c 1 in a not yet existing limb. It will not enlarge it if
 *                 the bit should be set to \c 0.
 *
 * \param X        The MPI to use.
 * \param pos      A zero-based index of the bit in \p X.
 * \param val      The value to set the bit to: \c 0 or \c 1.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \p val is not \c 0 or \c 1.
 */
int mbedtls_mpi_set_bit( mbedtls_mpi *X, size_t pos, unsigned char val );

/**
 * \brief          This function returns the number of zero-bits before the
 *                 least significant '1' bit. This is the zero-based index
 *                 of the least significant '1' bit.
 *
 * \param X        The MPI to use.
 */
size_t mbedtls_mpi_lsb( const mbedtls_mpi *X );

/**
 * \brief          This function returns the number of bits up to and including
 *                 the most significant '1' bit'. This is the one-based index
 *                 of the most significant '1' bit.
 *
 * \param X        The MPI to use.
 */
size_t mbedtls_mpi_bitlen( const mbedtls_mpi *X );

/**
 * \brief          This function returns the total size of the MPI in bytes.
 *
 * \param X        The MPI to use.
 */
size_t mbedtls_mpi_size( const mbedtls_mpi *X );

/**
 * \brief          This function imports an ASCII string to an the MPI
 *                 in \p X.
 *
 * \param X        The MPI to import the ASCII string to.
 * \param radix    The numeric base of the input.
 * \param s        The buffer containing the null-terminated string.
 *
 * \return         \c 0 on success.
 * \return         An #MBEDTLS_ERR_MPI_XXX error code on failure.
 */
int mbedtls_mpi_read_string( mbedtls_mpi *X, int radix, const char *s );

/**
 * \brief          This function exports an ASCII string from the MPI
 *                 in \p X to the buffer in \p buf.
 *
 *                 \p olen is always updated to reflect the amount
 *                 of data to be written.
 *
 * \note           Call this function with <code>buflen = 0</code> to obtain
 *                 the minimum required buffer size in \p olen.
 *
 * \param X        The MPI to export the ASCII string from.
 * \param radix    The numeric base of the output.
 * \param buf      The buffer to write the string to.
 * \param buflen   The length of \p buf.
 * \param olen     The length of the string written, including final the NULL
 *                 byte.
 *
 * \return         \c 0 on success.
 * \return         An #MBEDTLS_ERR_MPI_XXX error code on failure.
 */
int mbedtls_mpi_write_string( const mbedtls_mpi *X, int radix,
                              char *buf, size_t buflen, size_t *olen );

#if defined(MBEDTLS_FS_IO)
/**
 * \brief          This function reads a line in an opened file, interprets
 *                 it as an MPI, and writes it \p X.
 *
 *                 If successful, this function advances the file stream
 *                 to the end of the current line or to EOF.
 *
 *                 The function returns 0 on an empty line.
 *
 * \note           Leading whitespaces are ignored, as is a
 *                 '0x' prefix for <code>radix = 16</code>.
 *
 * \param X        The destination MPI.
 * \param radix    The numeric base of the input.
 * \param fin      The input file handle.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if
 *                 the file read buffer is too small.
 * \return         An \c MBEDTLS_ERR_MPI_XXX error code on failure.
 */
int mbedtls_mpi_read_file( mbedtls_mpi *X, int radix, FILE *fin );

/**
 * \brief          This function writes \p X into an opened file, or into
 *                 \p stdout if \p fout is NULL.
 *
 * \note           Setting <code>fout == NULL</code> prints \p X on the console.
 *
 * \param p        The arbitrary prefix before the number. Can be NULL.
 * \param X        The MPI to write into the file.
 * \param radix    The numeric base of the output.
 * \param fout     The handle of the output file. Can be NULL.
 *
 * \return         \c 0 on success.
  * \return        An \c MBEDTLS_ERR_MPI_XXX error code on failure.
 */
int mbedtls_mpi_write_file( const char *p, const mbedtls_mpi *X, int radix, FILE *fout );
#endif /* MBEDTLS_FS_IO */

/**
 * \brief          This function imports an unsigned binary data from \p buf,
 *                 in big-endian format, into \p X.
 *
 * \param X        The MPI to import the data to.
 * \param buf      The input buffer.
 * \param buflen   The size of the input buffer.
 *
 * \return         \c 0 on success,
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_read_binary( mbedtls_mpi *X, const unsigned char *buf, size_t buflen );

/**
 * \brief          This function exports \p X into unsigned binary data in
 *                 \p buf, in big-endian format.
 *
 *                 The function always fills the whole buffer. This means it
 *                 is padded with zeros if the size of \p X is smaller than
 *                 \p buflen.
 *
 * \param X        The MPI to export.
 * \param buf      The output buffer.
 * \param buflen   The size of the output buffer.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p buflen is smaller
 *                 than the size of \X.
 */
int mbedtls_mpi_write_binary( const mbedtls_mpi *X, unsigned char *buf, size_t buflen );

/**
 * \brief          This function shifts the bits in \p X to the left, in
 *                 the amount defined \p count and stores the result \p X
 *                 (Left-shift: X <<= count).
 *
 * \param X        The MPI to shift.
 * \param count    The amount to shift.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_shift_l( mbedtls_mpi *X, size_t count );

/**
 * \brief          This function shifts the bits in \p X to the right, in
 *                 the amount defined \p count and stores the result \p X
 *                 (Right-shift: X >>= count).
 *
 * \param X        The MPI to shift.
 * \param count    The amount to shift.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_shift_r( mbedtls_mpi *X, size_t count );

/**
 * \brief          This function compares two unsigned values.
 *
 * \param X        The first MPI to compare.
 * \param Y        The second MPI to compare.
 *
 * \return         \c 1 if \c |X| is greater than \c |Y|.
 * \return         \c -1 if \c |X| is lesser than \c |Y|.
 * \return         \c 0 if \c |X| is equal to \c |Y|.
 */
int mbedtls_mpi_cmp_abs( const mbedtls_mpi *X, const mbedtls_mpi *Y );

/**
 * \brief          This function compares two signed values.
 *
 * \param X        The first MPI to compare.
 * \param Y        The second MPI to compare.
 *
 * \return         \c 1 if \c X is greater than \c Y.
 * \return         \c -1 if \c X is lesser than \c Y.
 * \return         \c 0 if \c X is equal to \c Y.
 */
int mbedtls_mpi_cmp_mpi( const mbedtls_mpi *X, const mbedtls_mpi *Y );

/**
 * \brief          This function compares two signed values.
 *
 * \param X        The first MPI to compare.
 * \param z        The integer value to compare to.
 *
 * \return         \c 1 if \c X is greater than \c z.
 * \return         \c -1 if \c X is lesser than \c z.
 * \return         \c 0 if \c X is equal to \c z.
 */
int mbedtls_mpi_cmp_int( const mbedtls_mpi *X, mbedtls_mpi_sint z );

/**
 * \brief          This function performs an unsigned addition operation:
 *                 <code>X = |A| + |B|</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_add_abs( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
 * \brief          This function performs an unsigned subtraction operation:
 *                 <code>X = |A| - |B|</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if B is greater than A.
 */
int mbedtls_mpi_sub_abs( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
* \brief           This function performs a signed addition operation:
 *                 <code>X = A + B</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_add_mpi( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
 * \brief          This function performs an unsigned subtraction operation:
 *                 <code>X = A - B</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if B is greater than A.
 */
int mbedtls_mpi_sub_mpi( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
 * \brief          This function performs a signed addition operation:
 *                 <code>X = A + b</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param b        The integer value to add.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_add_int( mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_sint b );

/**
 * \brief          This function performs a signed subtraction operation:
 *                 <code>X = A - b</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param b        The integer value to subtract.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_sub_int( mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_sint b );

/**
 * \brief          This function performs a baseline multiplication operation:
 *                 <code>X = A * B</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_mul_mpi( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
 * \brief          This function performs a baseline multiplication operation:
 *                 <code>X = A * b</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param b        The unsigned integer value to multiply with.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_mul_int( mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_uint b );

/**
 * \brief          This function performs division by mbedtls_mpi:
 *                 <code>A = Q * B + R</code>.
 *
 * \note           Either \p Q or \p R can be NULL.
 *
 * \param Q        The destination MPI for the quotient.
 * \param R        The destination MPI for the remainder.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if <code>B == 0</code>.
 */
int mbedtls_mpi_div_mpi( mbedtls_mpi *Q, mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
 * \brief          This function performs division by int:
 *                 <code>A = Q * b + R</code>.
 *
 * \note           Either \p Q or \p R can be NULL.
 *
 * \param Q        The destination MPI for the quotient.
 * \param R        The destination MPI for the remainder.
 * \param A        The left-hand MPI.
 * \param b        The integer to divide by.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if <code>b == 0</code>.
 */
int mbedtls_mpi_div_int( mbedtls_mpi *Q, mbedtls_mpi *R, const mbedtls_mpi *A, mbedtls_mpi_sint b );

/**
 * \brief          This function performs a modulo operation:
 *                 <code>R = A mod B</code>.
 *
 * \param R        The destination MPI for the remainder.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if <code>B == 0</code>.
 * \return         #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if <code>B < 0</code>.
 */
int mbedtls_mpi_mod_mpi( mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
 * \brief          This function performs a modulo operation:
 *                 <code>r = A mod b</code>.
 *
 * \param r        The destination MPI.
 * \param A        The left-hand MPI.
 * \param b        The integer to divide by.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_DIVISION_BY_ZERO if <code>b == 0</code>.
 * \return         #MBEDTLS_ERR_MPI_NEGATIVE_VALUE if <code>b < 0</code>.
 */
int mbedtls_mpi_mod_int( mbedtls_mpi_uint *r, const mbedtls_mpi *A, mbedtls_mpi_sint b );

/**
 * \brief          This function performs a sliding-window exponentiation:
 *                 X = A^E mod N.
 *
 * \note           \p _RR is used to avoid re-computing <code>R*R mod N</code>
 *                 across multiple calls, which speeds up performance. It can
 *                 be set to NULL if the extra performance is unneeded.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param E        The MPI for the exponent.
 * \param N        The MPI for the modulus.
 * \param _RR      The MPI to store intermediate values that can be reused
 *                 to accelerate recalculations, when calling the function with
 *                 the same \p N.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if either \p N or \p E is
 *                 negative.
 */
int mbedtls_mpi_exp_mod( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *E, const mbedtls_mpi *N, mbedtls_mpi *_RR );

/**
 * \brief          This function fills the MPI in \p X with random bytes.
 *
 * \note           The bytes obtained from the PRNG are interpreted
 *                 as a big-endian representation of an MPI. This can
 *                 be relevant in applications like deterministic ECDSA.
 *
 * \param X        The destination MPI.
 * \param size     The size in bytes.
 * \param f_rng    The RNG function.
 * \param p_rng    The RNG context.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_fill_random( mbedtls_mpi *X, size_t size,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          This function calculates the greatest common divisor:
 *                 <code>G = gcd(A, B)</code>.
 *
 * \param G        The destination MPI.
 * \param A        The left-hand MPI.
 * \param B        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 */
int mbedtls_mpi_gcd( mbedtls_mpi *G, const mbedtls_mpi *A, const mbedtls_mpi *B );

/**
 * \brief          This function performs an inverse modulo operation:
 *                 <code>X = A^-1 mod N</code>.
 *
 * \param X        The destination MPI.
 * \param A        The left-hand MPI.
 * \param N        The right-hand MPI.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if <code>N <= 1</code>.
 * \return         #MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if \p A has no inverse
 *                 mod \p N.
 */
int mbedtls_mpi_inv_mod( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N );

/**
 * \brief          This function performs a Miller-Rabin primality test.
 *
 * \param X        The MPI to check.
 * \param f_rng    Thw RNG function.
 * \param p_rng    The RNG context.
 *
 * \return         \c 0 on success (probably prime).
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if X is not a prime.
 */
int mbedtls_mpi_is_prime( const mbedtls_mpi *X,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng );

/**
 * \brief          This function generates a prime number.
 *
 * \param X        The destination MPI.
 * \param nbits    The required size of \p X in bits:
 *                 <code>( 3 <= nbits <= MBEDTLS_MPI_MAX_BITS )</code>
 * \param dh_flag  If 1, then <code>(X-1)/2</code> is also a prime.
 * \param f_rng    The RNG function.
 * \param p_rng    The RNG context.
 *
 * \return         \c 0 on success (probably prime).
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED on memory-allocation failure.
 * \return         #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if <code>nbits < 3</code>.
 */
int mbedtls_mpi_gen_prime( mbedtls_mpi *X, size_t nbits, int dh_flag,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void *p_rng );

/**
 * \brief          The BigNum checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int mbedtls_mpi_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* bignum.h */
