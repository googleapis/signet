#!groovy
@Library("liveramp-base@v1") _

pipeline {
  options {
    ansiColor('xterm')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '50', daysToKeepStr: '30'))
  }

  triggers {
    githubPush()
    snapshotDependencies()
    issueCommentTrigger('.*jenkins\\W+(((test|build|run|do)\\W+this)|again|git\\W+r\\W+done|please|make it so).*')
  }

  agent any

  stages {
    stage('push') {
      when { branch 'master' }
      steps {
        withCredentials(bindings: [
          usernamePassword(credentialsId: 'library.liveramp.net--jenkins_publisher',
                           usernameVariable: 'ARTIFACTORY_USERNAME',
                           passwordVariable: 'ARTIFACTORY_PASSWORD')
        ]) {
          sh "bundle install"
          sh "bundle exec rake push"
        }
      }
    }
  }

  post {
    always {
      slackNotification('#dev-ops-builds', 'master')
    }
  }
}
