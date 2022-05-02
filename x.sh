cd /pwd
ls -l
pip install -r requirements-dev.txt
pip install -r requirements.txt
pwd 
python3 -m unittest -v tests/test_pytmfunc.py
ls