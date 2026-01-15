cd /var/app/volumes/winp2/app
rm -r winp2.dist
nuitka --standalone --include-module=httpx winp2.py
cp -r winp2.dist/* /var/app/volumes/release/app/
cd ../
cp ./*.conf /var/app/volumes/conf/
