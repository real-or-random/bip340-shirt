def schnorr_verify(m, p, s): # msg, pubkey, sig
 I=int;B=lambda v:I.from_bytes(v,"big");import\
 hashlib as h; H=lambda x: h.sha256(x).digest()
 P=2**256-2**32-977;T=2*H(b"BIP0340/challenge")
 L=lambda x: (c:=x**3+7,y:=pow(c,1+P//4,P),(x<P
 and 0==(c-y*y)%P)and(x,-y*(-1)**y%P))[2];C=len
 A=lambda p,q:p or q if not(p and q)else(x:=p[0
 ],y:=p[1],f:=(q[1]-y,3*x**2,q[0]-x,2*y),l:=f[q
 ==p]*pow(f[2+(q==p)],P-2,P),X:=(l*l-x-q[0])%P,
 X and(X,(l*(x-X)-y)%P))[5];K=L(B(p));D=lambda\
 x:A(x,x);M=lambda p,k:k and A(k&1 and p,D(M(p,
 k//2)));N=P-I("j9cdktuvdh95srl1uibgen5ri",36);
 G=D(L(I("1defdm6hgyrgjeubdk5wujq5eiukgejxf",36
 )));S=B(s[32:]);r=B(s[:32]);t=A(M(G,S),M(K,N-B
 (H(T+s[:32]+p+m))%N)); return K and t and(2*C(
 p)==C(s)==64)*(r<P)*(S<N)*(t[1]&1)*(t[0]==r)>0
