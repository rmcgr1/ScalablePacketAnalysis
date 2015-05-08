#!/bin/bash

for i in `ls | grep chunk`; do tshark -r ./$i -T fields -e ip.src -e dns.qry.name -R 'dns.flags.response eq 0' | wc -l; done | perl -e 'use List::Util qw(max min sum); @a=();while(<>){$sqsum+=$_*$_; push(@a,$_)}; $n=@a;$s=sum(@a);$a=$s/@a;$m=max(@a);$mm=min(@a);$std=sqrt($sqsum/$n-($s/$n)*($s/$n));$mid=int @a/2;@srtd=sort @a;if(@a%2){$med=$srtd[$mid];}else{$med=($srtd[$mid-1]+$srtd[$mid])/2;};print "records:$n\nsum:$s\navg:$a\nstd:$std\nmed:$med\max:$m\min:$mm";'
