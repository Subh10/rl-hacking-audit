from __future__ import annotations
import math
def wilson(k,n,z=1.96):
    if n<=0:return 0.0,1.0
    p=k/n; denom=1+z*z/n; centre=(p+z*z/(2*n))/denom; half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/denom
    return max(0.0,centre-half),min(1.0,centre+half)
def _lchoose(n,k):return math.lgamma(n+1)-math.lgamma(k+1)-math.lgamma(n-k+1)
def fisher_exact(k1,n1,k2,n2):
    if min(n1,n2)<=0:return 1.0
    total_k,total_n=k1+k2,n1+n2
    def logp(x):return _lchoose(n1,x)+_lchoose(n2,total_k-x)-_lchoose(total_n,total_k)
    lo,hi=max(0,total_k-n2),min(n1,total_k); observed=logp(k1); return min(1.0,sum(math.exp(lp) for x in range(lo,hi+1) if (lp:=logp(x))<=observed+1e-9))
def holm(pvalues):
    m=len(pvalues); order=sorted(range(m),key=lambda i:pvalues[i]); adjusted=[0.0]*m; running=0.0
    for rank,idx in enumerate(order):running=max(running,min(1.0,(m-rank)*pvalues[idx])); adjusted[idx]=running
    return adjusted
