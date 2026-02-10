#!/usr/bin/env bash
set -ex

CHROME_ARGS="--password-store=basic --no-sandbox --ignore-gpu-blocklist --user-data-dir --no-first-run --disable-search-engine-choice-screen --disable-infobars --simulate-outdated-no-au='Tue, 31 Dec 2099 23:59:59 GMT'"
CHROME_VERSION=$1
CHROME_VARIANT="${CHROME_VARIANT:-cft}"

ARCH=$(arch | sed 's/aarch64/arm64/g' | sed 's/x86_64/amd64/g')
if [ "$ARCH" == "arm64" ] ; then
  echo "Chrome not supported on arm64, skipping Chrome installation"
  exit 0
fi	

install_google_chrome_stable() {
  if [[ "${DISTRO}" == @(centos|oracle8|rockylinux9|rockylinux8|oracle9|rhel9|almalinux9|almalinux8) ]]; then
    if [ -n "${CHROME_VERSION}" ]; then
      wget https://dl.google.com/linux/chrome/rpm/stable/x86_64/google-chrome-stable-${CHROME_VERSION}.x86_64.rpm -O chrome.rpm
    else
      wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm -O chrome.rpm
    fi
    if [[ "${DISTRO}" == @(oracle8|rockylinux9|rockylinux8|oracle9|rhel9|almalinux9|almalinux8) ]]; then
      dnf localinstall -y chrome.rpm
      if [ -z ${SKIP_CLEAN+x} ]; then
        dnf clean all
      fi
    else
      yum localinstall -y chrome.rpm
      if [ -z ${SKIP_CLEAN+x} ]; then
        yum clean all
      fi
    fi
    rm chrome.rpm
  elif [ "${DISTRO}" == "opensuse" ]; then
    zypper ar http://dl.google.com/linux/chrome/rpm/stable/x86_64 Google-Chrome
    wget https://dl.google.com/linux/linux_signing_key.pub
    rpm --import linux_signing_key.pub
    rm linux_signing_key.pub
    zypper install -yn google-chrome-stable
    if [ -z ${SKIP_CLEAN+x} ]; then
      zypper clean --all
    fi
  else
    apt-get update
    if [ -n "${CHROME_VERSION}" ]; then
      wget https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${CHROME_VERSION}_amd64.deb -O chrome.deb
    else
      wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O chrome.deb
    fi
    apt-get install -y ./chrome.deb
    rm chrome.deb
    if [ -z ${SKIP_CLEAN+x} ]; then
      apt-get autoclean
      rm -rf \
        /var/lib/apt/lists/* \
        /var/tmp/*
    fi
  fi
}

ensure_unzip() {
  if command -v unzip >/dev/null 2>&1 ; then
    return
  fi

  if [[ "${DISTRO}" == @(centos|oracle8|rockylinux9|rockylinux8|oracle9|rhel9|almalinux9|almalinux8) ]]; then
    if [[ "${DISTRO}" == @(oracle8|rockylinux9|rockylinux8|oracle9|rhel9|almalinux9|almalinux8) ]]; then
      dnf install -y unzip
    else
      yum install -y unzip
    fi
  elif [ "${DISTRO}" == "opensuse" ]; then
    zypper install -yn unzip
  else
    apt-get update
    apt-get install -y unzip
  fi
}

install_chrome_for_testing() {
  ensure_unzip

  if [ -n "${CHROME_VERSION}" ]; then
    CFT_VERSION="${CHROME_VERSION}"
  else
    CFT_VERSION="$(wget -qO- https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_STABLE || true)"
    if [ -z "${CFT_VERSION}" ]; then
      CFT_VERSION="$(wget -qO- https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE || true)"
    fi
    if [ -z "${CFT_VERSION}" ]; then
      echo "Unable to resolve Chrome for Testing stable version"
      exit 1
    fi
  fi

  CFT_PLATFORM="linux64"
  CFT_URL="https://storage.googleapis.com/chrome-for-testing-public/${CFT_VERSION}/${CFT_PLATFORM}/chrome-${CFT_PLATFORM}.zip"
  wget "${CFT_URL}" -O /tmp/chrome-for-testing.zip

  rm -rf /opt/chrome-for-testing
  mkdir -p /opt/chrome-for-testing
  unzip -q /tmp/chrome-for-testing.zip -d /opt/chrome-for-testing
  rm -f /tmp/chrome-for-testing.zip

  mkdir -p /opt/google/chrome
  ln -sf /opt/chrome-for-testing/chrome-${CFT_PLATFORM}/chrome /opt/google/chrome/google-chrome

  if [ ! -f /usr/share/applications/google-chrome.desktop ] ; then
    cat >/usr/share/applications/google-chrome.desktop <<EOF
[Desktop Entry]
Version=1.0
Name=Google Chrome
Comment=Access the Internet
Exec=/usr/bin/google-chrome %U
Terminal=false
Type=Application
Icon=google-chrome
Categories=Network;WebBrowser;
StartupNotify=true
EOF
  fi

  if [ -z ${SKIP_CLEAN+x} ]; then
    if [ -x "$(command -v apt-get)" ]; then
      apt-get autoclean || true
      rm -rf /var/lib/apt/lists/* /var/tmp/*
    elif [ -x "$(command -v dnf)" ]; then
      dnf clean all || true
    elif [ -x "$(command -v yum)" ]; then
      yum clean all || true
    elif [ -x "$(command -v zypper)" ]; then
      zypper clean --all || true
    fi
  fi
}

if [ "${CHROME_VARIANT}" = "stable" ] ; then
  install_google_chrome_stable
else
  install_chrome_for_testing
fi

if [ -f /usr/share/applications/google-chrome.desktop ] ; then
  sed -i 's/-stable//g' /usr/share/applications/google-chrome.desktop
fi

if [ -f /usr/share/applications/google-chrome.desktop ] ; then
  cp /usr/share/applications/google-chrome.desktop $HOME/Desktop/
  chown 1000:1000 $HOME/Desktop/google-chrome.desktop
  chmod +x $HOME/Desktop/google-chrome.desktop
fi

if [ -x /usr/bin/google-chrome ] ; then
  mv /usr/bin/google-chrome /usr/bin/google-chrome-orig
fi
cat >/usr/bin/google-chrome <<EOL
#!/usr/bin/env bash
if ! pgrep chrome > /dev/null;then
  rm -f \$HOME/.config/google-chrome/Singleton*
fi
sed -i 's/"exited_cleanly":false/"exited_cleanly":true/' ~/.config/google-chrome/Default/Preferences
sed -i 's/"exit_type":"Crashed"/"exit_type":"None"/' ~/.config/google-chrome/Default/Preferences
if [ -f /opt/VirtualGL/bin/vglrun ] && [ ! -z "\${KASM_EGL_CARD}" ] && [ ! -z "\${KASM_RENDERD}" ] && [ -O "\${KASM_RENDERD}" ] && [ -O "\${KASM_EGL_CARD}" ] ; then
    echo "Starting Chrome with GPU Acceleration on EGL device \${KASM_EGL_CARD}"
    vglrun -d "\${KASM_EGL_CARD}" /opt/google/chrome/google-chrome ${CHROME_ARGS} "\$@" 
else
    echo "Starting Chrome"
    /opt/google/chrome/google-chrome ${CHROME_ARGS} "\$@"
fi
EOL
chmod +x /usr/bin/google-chrome
cp /usr/bin/google-chrome /usr/bin/chrome

if [[ "${DISTRO}" == @(centos|oracle8|rockylinux9|rockylinux8|oracle9|rhel9|almalinux9|almalinux8|opensuse) ]]; then
  cat >> $HOME/.config/mimeapps.list <<EOF
    [Default Applications]
    x-scheme-handler/http=google-chrome.desktop
    x-scheme-handler/https=google-chrome.desktop
    x-scheme-handler/ftp=google-chrome.desktop
    x-scheme-handler/chrome=google-chrome.desktop
    text/html=google-chrome.desktop
    application/x-extension-htm=google-chrome.desktop
    application/x-extension-html=google-chrome.desktop
    application/x-extension-shtml=google-chrome.desktop
    application/xhtml+xml=google-chrome.desktop
    application/x-extension-xhtml=google-chrome.desktop
    application/x-extension-xht=google-chrome.desktop
EOF
else
  if [ -f /usr/bin/x-www-browser ] ; then
    sed -i 's@exec -a "$0" "$HERE/google-chrome" "$\@"@@g' /usr/bin/x-www-browser
    cat >>/usr/bin/x-www-browser <<EOL
  exec -a "\$0" "\$HERE/chrome" "${CHROME_ARGS}"  "\$@"
EOL
  else
    cat >/usr/bin/x-www-browser <<EOL
#!/usr/bin/env bash
exec -a "\$0" "/usr/bin/chrome" "${CHROME_ARGS}" "\$@"
EOL
    chmod +x /usr/bin/x-www-browser
  fi
fi

mkdir -p /etc/opt/chrome/policies/managed/
cat >>/etc/opt/chrome/policies/managed/default_managed_policy.json <<EOL
{"CommandLineFlagSecurityWarningsEnabled": false, "DefaultBrowserSettingEnabled": false, "PrivacySandboxPromptEnabled": false}
EOL

# Cleanup for app layer
chown -R 1000:0 $HOME
find /usr/share/ -name "icon-theme.cache" -exec rm -f {} \;
