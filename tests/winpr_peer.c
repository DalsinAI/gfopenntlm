/* tests/winpr_peer.c: an optional black-box interoperability check, not
 * part of the build. It runs gfopenntlm's CredSSP client against WinPR's
 * NTLM server (FreeRDP 3, the server GNOME Remote Desktop uses) through
 * the SSPI calls Microsoft documents (AcquireCredentialsHandle,
 * AcceptSecurityContext, DecryptMessage, EncryptMessage), with the
 * TSRequests passed in memory and a fixed stand-in public key. WinPR is
 * only built and run; none of its source is read or used here.
 *
 *   winpr-hash -u da1ek -p test123 -f sam > <WinPR's SAM file>
 *   cc -I include -I src -I <winpr include dirs> -o winpr_peer \
 *      tests/winpr_peer.c src/gn_*.c (not gn_api.c, gn_sys_amiga.c) -lwinpr
 *   ./winpr_peer da1ek "" test123 [version]
 *
 * It writes neg.bin, chal.bin, auth.bin, exported.bin, nonce.bin and
 * pkauth.der, the source of tests/winpr_transcript.h.
 * MIT, Copyright (c) 2026 AmiCradle Team. Written by Sacredtrees (Team 6). */
#include <winpr/sspi.h>
#include <winpr/wlog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gn_internal.h"
static void dump(const char *n,const uint8_t *p,size_t l){ FILE*f=fopen(n,"wb"); fwrite(p,1,l,f); fclose(f);}
static void hex(const char*t,const uint8_t*p,size_t l){printf("%s:",t);for(size_t i=0;i<l;i++)printf("%02x",p[i]);printf("\n");}
int main(int argc,char**argv){
  const char *user=argc>1?argv[1]:"da1ek", *dom=argc>2?argv[2]:"", *pw=argc>3?argv[3]:"test123";
  int maxv=argc>4?atoi(argv[4]):6;
  static const uint8_t pub[270]={0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00,0xc3}; /* fake SubjectPublicKey */
  const SecurityFunctionTableA *T=InitSecurityInterfaceExA(0);
  CredHandle cred; TimeStamp ts; CtxtHandle ctx; int have=0;
  SECURITY_STATUS st=T->AcquireCredentialsHandleA(NULL,"NTLM",SECPKG_CRED_INBOUND,NULL,NULL,NULL,NULL,&cred,&ts);
  printf("AcquireCredentialsHandle 0x%08X\n",(unsigned)st);
  struct gn_cssp c; gn_cssp_init(&c,user,dom,pw,"AMIGA","daletop",pub,sizeof pub,maxv);
  static uint8_t a[16384],b[16384]; size_t al; int e; struct gn_tsrequest r,q;
  e=gn_cssp_step(&c,NULL,0,a,sizeof a,&al); printf("client step0 %d\n",e);
  for(int round=0;round<2;round++){
    gn_tsrequest_decode(a,al,&r);
    dump(round?"auth.bin":"neg.bin",r.nego_token,r.nego_token_len);
    SecBuffer ib={ (ULONG)r.nego_token_len, SECBUFFER_TOKEN, (void*)r.nego_token }; SecBufferDesc id={SECBUFFER_VERSION,1,&ib};
    static uint8_t ob[8192]; SecBuffer obb={sizeof ob,SECBUFFER_TOKEN,ob}; SecBufferDesc od={SECBUFFER_VERSION,1,&obb};
    ULONG attr; st=T->AcceptSecurityContext(&cred,have?&ctx:NULL,&id,ASC_REQ_CONFIDENTIALITY|ASC_REQ_CONNECTION|ASC_REQ_USE_SESSION_KEY|ASC_REQ_REPLAY_DETECT|ASC_REQ_SEQUENCE_DETECT|ASC_REQ_EXTENDED_ERROR,SECURITY_NATIVE_DREP,&ctx,&od,&attr,&ts);
    have=1; printf("AcceptSecurityContext round %d: 0x%08X out %lu\n",round,(unsigned)st,(unsigned long)obb.cbBuffer);
    if(round==0){
      if(st!=SEC_I_CONTINUE_NEEDED) return 1;
      dump("chal.bin",ob,obb.cbBuffer);
      memset(&q,0,sizeof q); q.version=6; q.nego_token=ob; q.nego_token_len=obb.cbBuffer;
      size_t bl=gn_tsrequest_encode(&q,b,sizeof b);
      e=gn_cssp_step(&c,b,bl,a,sizeof a,&al); printf("client step1 %d\n",e); if(e<0) return 2;
    } else {
      if(st!=SEC_E_OK){ printf("NTLM AUTHENTICATE rejected\n"); return 3; }
      printf("NTLM AUTHENTICATE accepted (MIC verified)\n"); dump("exported.bin",c.ntlm.exported_key,16); dump("nonce.bin",c.nonce,32); dump("pkauth.der",a,al);
      /* pubKeyAuth */
      uint8_t buf[512]; memcpy(buf,r.pub_key_auth,r.pub_key_auth_len);
      SecBuffer db[2]={{16,SECBUFFER_TOKEN,buf},{(ULONG)r.pub_key_auth_len-16,SECBUFFER_DATA,buf+16}}; SecBufferDesc dd={SECBUFFER_VERSION,2,db};
      ULONG qop; st=T->DecryptMessage(&ctx,&dd,0,&qop); printf("DecryptMessage(pubKeyAuth) 0x%08X len %lu\n",(unsigned)st,(unsigned long)db[1].cbBuffer);
      uint8_t want[32]; gn_cssp_hash("CredSSP Client-To-Server Binding Hash",c.nonce,pub,sizeof pub,want);
      if(c.version>=5) printf("pubKeyAuth hash %s\n", (db[1].cbBuffer==32&&!memcmp(db[1].pvBuffer,want,32))?"matches":"WRONG");
      else printf("pubKeyAuth v%u key %s\n",c.version,(db[1].cbBuffer==sizeof pub&&!memcmp(db[1].pvBuffer,pub,sizeof pub))?"matches":"WRONG");
      /* server answer */
      uint8_t sb[16+300]; size_t sl;
      if(c.version>=5){ gn_cssp_hash("CredSSP Server-To-Client Binding Hash",c.nonce,pub,sizeof pub,sb+16); sl=32; }
      else { memcpy(sb+16,pub,sizeof pub); sb[16]++; sl=sizeof pub; }
      SecBuffer eb[2]={{16,SECBUFFER_TOKEN,sb},{(ULONG)sl,SECBUFFER_DATA,sb+16}}; SecBufferDesc ed={SECBUFFER_VERSION,2,eb};
      st=T->EncryptMessage(&ctx,0,&ed,0); printf("EncryptMessage 0x%08X sig %lu\n",(unsigned)st,(unsigned long)eb[0].cbBuffer);
      memset(&q,0,sizeof q); q.version=6; q.pub_key_auth=sb; q.pub_key_auth_len=16+sl;
      size_t bl=gn_tsrequest_encode(&q,b,sizeof b);
      e=gn_cssp_step(&c,b,bl,a,sizeof a,&al); printf("client step2 (verify server pubKeyAuth, send TSCredentials) %d\n",e); if(e) return 4;
      gn_tsrequest_decode(a,al,&r); memcpy(buf,r.auth_info,r.auth_info_len);
      SecBuffer cb[2]={{16,SECBUFFER_TOKEN,buf},{(ULONG)r.auth_info_len-16,SECBUFFER_DATA,buf+16}}; SecBufferDesc cd={SECBUFFER_VERSION,2,cb};
      st=T->DecryptMessage(&ctx,&cd,1,&qop); printf("DecryptMessage(authInfo) 0x%08X len %lu\n",(unsigned)st,(unsigned long)cb[1].cbBuffer);
      if(st==SEC_E_OK){ uint8_t *p=cb[1].pvBuffer; printf("TSCredentials starts %02x %02x, credType tag %02x\n",p[0],p[1],p[2]); }
      return st==SEC_E_OK?0:5;
    }
  }
  return 0; }
