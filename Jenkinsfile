def serverCredentials = []
def ARTIFACTORY_CREDENTIALS_ID = 'zowe.jfrog.io'
Map TEST_SERVERS = [
        'marist'  : [
                ansible_host     : 'marist-1',
                ssh_hostport     : 'ssh-marist-server-zzow01-hostport',
                ssh_userpass     : 'ssh-marist-server-zzow01',
                node_home_pattern: '/ZOWE/node/node-{NODE_VERSION}-os390-s390x'
        ],
        'marist-2': [
                ansible_host: 'marist-2',
                ssh_hostport: 'ssh-marist-server-zzow02-hostport',
                ssh_userpass: 'ssh-marist-server-zzow02'
        ],
        'marist-3': [
                ansible_host: 'marist-3',
                ssh_hostport: 'ssh-marist-server-zzow03-hostport',
                ssh_userpass: 'ssh-marist-server-zzow03'
        ]
];
TEST_SERVERS.each { key, host ->
    def hostKey = host['ansible_host'].replaceAll(/[^A-Za-z0-9]/, '_').toUpperCase()
    serverCredentials.add(usernamePassword(
            credentialsId: host['ssh_hostport'],
            passwordVariable: "${hostKey}_SSH_PORT".toString(),
            usernameVariable: "${hostKey}_SSH_HOST".toString()
    ))
    serverCredentials.add(usernamePassword(
            credentialsId: host['ssh_userpass'],
            passwordVariable: "${hostKey}_SSH_PASSWORD".toString(),
            usernameVariable: "${hostKey}_SSH_USER".toString()
    ))
}
pipeline {

    agent {
        label 'zowe-jenkins-agent'
    }

    parameters {
        booleanParam(name: 'RELEASE', defaultValue: false, description: 'Toggle this to publish release')
        booleanParam(name: 'SNAPSHOT', defaultValue: false, description: 'Toggle this to publish snapshot')
    }
    stages {


        stage('Install tools') {
            steps {
                sh 'npm install -g @zowe/cli'
                sh 'npm -g install @zowedev/zowe-api-dev'
            }
        }

        stage('Build') {
            steps {

                    withCredentials(serverCredentials) {
                        sh "zowe profiles create ssh-profile maristzowe --host ${MARIST_1_SSH_HOST} --port ${MARIST_1_SSH_PORT} --user ${MARIST_1_SSH_USER} --password ${MARIST_1_SSH_PASSWORD}"
                        sh "zowe profiles create zosmf-profile maristzowe --host ${MARIST_1_SSH_HOST} --port 10443 --user ${MARIST_1_SSH_USER} --pass ${MARIST_1_SSH_PASSWORD} --reject-unauthorized false"
                        sh "./gradlew :attls:zosbuild"
                        sh "./gradlew build"
                    }

            }
        }

        stage('Publish snapshot version to Artifactory for master') {
            steps {

                    withCredentials([usernamePassword(credentialsId: ARTIFACTORY_CREDENTIALS_ID, usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                        script {
                            if (params.SNAPSHOT) {
                                sh '''
                 ./gradlew publish -x test -Pzowe.deploy.username=$USERNAME -Pzowe.deploy.password=$PASSWORD -Partifactory_user=$USERNAME -Partifactory_password=$PASSWORD
                 '''
                            }
                            if (params.RELEASE) {
                                sh '''
                 ./gradlew release -x test -Prelease.useAutomaticVersion=true -Pzowe.deploy.username=$USERNAME -Pzowe.deploy.password=$PASSWORD -Partifactory_user=$USERNAME -Partifactory_password=$PASSWORD
                 '''
                            }
                        }
                    }

            }
        }
    }
}