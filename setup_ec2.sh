#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e

echo "=================================================="
echo "🛡️  Starting Agent WAF EC2 Automated Installation"
echo "=================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo: sudo bash setup_ec2.sh"
  exit 1
fi

# Determine script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "Step 1: Installing System Dependencies..."
apt-get update
apt-get install -y python3-pip python3-venv git nginx sqlite3 certbot python3-certbot-nginx

echo "Step 2: Creating Python Virtual Environment..."
if [ ! -d "venv" ]; then
  python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Step 3: Configuring Environment Credentials..."
if [ ! -f ".env" ] || ! grep -q "GROQ_API_KEY=" .env; then
  echo "Please enter your Groq API Key:"
  read -r -p "GROQ_API_KEY: " API_KEY
  echo "GROQ_API_KEY=$API_KEY" > .env
  echo "Created .env configuration file."
else
  echo ".env already configured."
fi

# Ensure reports directory exists
mkdir -p reports
chmod 777 reports

echo "Step 4: Configuring systemd Services..."
# Backend Service
cat <<EOF > /etc/systemd/system/waf-backend.service
[Unit]
Description=FastAPI Agent WAF Backend
After=network.target

[Service]
User=ubuntu
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/venv/bin/python -m uvicorn proxy.main:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Streamlit Service
cat <<EOF > /etc/systemd/system/waf-streamlit.service
[Unit]
Description=Streamlit WAF Client
After=network.target

[Service]
User=ubuntu
WorkingDirectory=$SCRIPT_DIR
Environment="STREAMLIT_SERVER_PORT=8501"
Environment="STREAMLIT_SERVER_ADDRESS=127.0.0.1"
ExecStart=$SCRIPT_DIR/venv/bin/streamlit run streamlit_app.py --server.headless=true
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "Step 5: Enabling and Starting systemd Services..."
systemctl daemon-reload
systemctl start waf-backend
systemctl start waf-streamlit
systemctl enable waf-backend
systemctl enable waf-streamlit

echo "Step 6: Configuring Nginx Reverse Proxy..."
# Remove default config
rm -f /etc/nginx/sites-enabled/default

# Create WAF config
cat <<EOF > /etc/nginx/sites-available/waf-app
server {
    listen 80;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/waf-app /etc/nginx/sites-enabled/

# Test and restart Nginx
nginx -t
systemctl restart nginx

echo "=================================================="
echo "🎉  Installation Complete!"
echo "=================================================="
echo "You can access your WAF Client by visiting the public IP of this EC2 instance."
echo ""
echo "To secure your instance with Let's Encrypt SSL, run:"
echo "  sudo certbot --nginx -d yourdomain.com"
echo "=================================================="
