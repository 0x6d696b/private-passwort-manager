pipeline {
    agent { label 'private-vault-pi' }
    options {
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
        timeout(time: 120, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }
    triggers { pollSCM('H/2 * * * *') }
    environment {
        CARGO_BUILD_JOBS = '1'
    }
    stages {
        stage('Checkout main') {
            steps {
                deleteDir()
                checkout scm
                sh 'test "$(git rev-parse HEAD)" = "$(git rev-parse refs/remotes/origin/main)"'
            }
        }
        stage('Verify') {
            steps {
                sh '''
                    set -eu
                    python3 scripts/verify_vendor.py
                    npm --prefix client ci --ignore-scripts
                    npm --prefix client audit --audit-level=low
                    npm --prefix client test
                    npm --prefix client run build
                    cargo +stable fmt --all -- --check
                    cargo +stable clippy --locked --all-targets -- -D warnings
                    cargo +stable test --locked --all-targets
                    cargo +stable audit
                    python3 -m unittest discover -s tests -p 'test_*.py'
                '''
            }
        }
        stage('Build and deploy') {
            steps {
                sh 'python3 scripts/deploy_pi.py'
            }
        }
    }
}
