/**
 * Update AWS security groups with Google IP addresses
 */

pipeline {

    agent any

    parameters {
        gitParameter(branch: '',
            branchFilter: 'origin/(.*)',
            defaultValue: 'master',
            description: 'Branch to fetch',
            name: 'branchName',
            quickFilterEnabled: false,
            selectedValue: 'NONE',
            sortMode: 'NONE',
            tagFilter: '*',
            type: 'PT_BRANCH'
        )
    }

    triggers { cron('55 * * * *') }

    options {
        disableConcurrentBuilds()
    }

    stages {

        stage('echo branch') {

            steps {
                sh """
                    echo "branchName: ${params.branchName}"
                """
            }
        }

        stage('Install requirements') {

            steps {
                sh """
                    /usr/bin/python -m pip install -r requirements.txt
                """
            }
        }

        stage('execute main.py') {

            steps {
                echo "Running SG update"
                sh """
                    /usr/bin/python main.py
                """
            }
        }
    }

}