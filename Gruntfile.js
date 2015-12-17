'use strict';

module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({

    env: {
      options: {
        // This is useless until the following PR is merged and released:
        //   https://github.com/alex-seville/travis-cov/pull/9
        TRAVIS_COV_THRESHOLD: 100
      },
      dev: {
        NODE_ENV: 'development'
      },
      travis: {
        NODE_ENV: 'production'
      }
    },

    // Task configuration.
    jshint: {
      options: {
        jshintrc: true
      },
      gruntfile: {
        src: ['Gruntfile.js']
      },
      src: {
        src: ['index.js', 'src/**/*.js', 'lib/**/*.js']
      },
      test: {
        src: ['test/**/*.js']
      }
    },

    mochacov: {
      options: {
        files: ['test/**/*.spec.js']
      },
      test: {
        options: {
          reporter: 'spec'
        }
      },
      /*
        NOTE: The `htmlcov` task is only here for IF you need/want to view the
        coverage result details! To do so, run `grunt showcoverage`
      */
      htmlcov: {
        options: {
          reporter: 'html-cov',
          output: 'coverage/index.html'
        }
      },
      coverage: {
        options: {
          reporter: 'travis-cov'
        }
      },
      coveralls: {
        options: {
          coveralls: true
        }
      }
    },

    open: {
      /*
        NOTE: The `htmlcov` task is only here for IF you need/want to view the
        coverage result details! To do so, run `grunt showcoverage`
      */
      htmlcov: {
        path: '<%= mochacov.htmlcov.options.output %>',
        app: 'Google Chrome'
      }
    }

  });


  // These plugins provide necessary tasks.
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-env');
  grunt.loadNpmTasks('grunt-mocha-cov');
  grunt.loadNpmTasks('grunt-open');

  // Default task.
  grunt.registerTask('default', ['env:dev', 'jshint', 'mochacov:test', 'mochacov:coverage']);

  // Travis CI task.
  grunt.registerTask('travis', ['env:travis', 'jshint', 'mochacov:test', 'mochacov:coverage', 'mochacov:coveralls']);

  // Special task to view HTML coverage results locally.
  grunt.registerTask('showcoverage', ['env:dev', 'mochacov:htmlcov', 'open:htmlcov']);

};
