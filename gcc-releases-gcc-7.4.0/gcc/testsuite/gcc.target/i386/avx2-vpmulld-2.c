/* { dg-do run } */
/* { dg-options "-mavx2 -O2" } */
/* { dg-require-effective-target avx2 } */

#include "avx2-check.h"

static void
compute_pmulld256 (int *s1, int *s2, int *r)
{
  int i;

  for (i = 0; i < 8; i++)
    r[i] = (int) ((long long int) s1[i] * (long long int) s2[i]);
}

static void
avx2_test (void)
{
  union256i_d s1, s2, res;
  int res_ref[8];
  int i, j, sign = 1;
  int fail = 0;

  for (i = 0; i < 10; i++)
    {
      for (j = 0; j < 8; j++)
	{
	  s1.a[j] = i * j * sign;
	  s2.a[j] = (j + 20) * sign;
	  sign = -sign;
	}

      res.x = _mm256_mullo_epi32 (s1.x, s2.x);

      compute_pmulld256 (s1.a, s2.a, res_ref);

      fail += check_union256i_d (res, res_ref);
    }

  if (fail != 0)
    abort ();
}
