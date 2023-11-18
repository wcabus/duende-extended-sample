/*
	Gulp tasks for: AdminUI Docker and TailwindCSS
	Author: Sam and Karl
*/

var gulp = require('gulp');
var cssimport = require("gulp-cssimport");
var postcss = require('gulp-postcss');
var purgecss = require('gulp-purgecss');
var rename = require('gulp-rename');
var tailwindcss = require('tailwindcss');
var uglifycss = require('gulp-uglifycss');

// paths
var tailwind_dir = './tailwind/';
var tailwind_output_dir = './assets/styles/';

// custom purgecss extractor(s) https://github.com/FullHuman/purgecss
TailwindExtractor = (content) => {
    return content.match(/[A-z0-9-:\/]+/g);
};

// tailwind_build
function tailwind_build() {
    return gulp.src(tailwind_dir + 'app.css')
        .pipe(cssimport())
        .pipe(postcss([
            tailwindcss(tailwind_dir + 'tailwind.config.js'),
            require('postcss-nested'),
            require('autoprefixer')
        ]))
        .pipe(uglifycss({
            "maxLineLen": 312,
            "uglyComments": true
        }))
        .pipe(rename({ suffix: '.min' }))
        .pipe(gulp.dest(tailwind_output_dir));
}

//tailwind_purge
function tailwind_purge() {
    return gulp.src(tailwind_output_dir + 'app.min.css')
        .pipe(purgecss({
            content: ['./**/*.html', './**/*.js'],
            extractors: [{
                extractor: TailwindExtractor,
                extensions: ['html', 'ts']
            }],
            safelist: {
                deep: [/alert/, /toast/, /ngx-toastr/, /cms/, /hide-tabs/]
            }
        }))
        .pipe(gulp.dest(tailwind_output_dir));
}
// tailwind_watcher
function tailwind_watcher() {
    gulp.watch([tailwind_dir + '**/*.*'], tailwind_build);
}

const dev = gulp.series(tailwind_build);
const build = gulp.series(tailwind_build, tailwind_purge);
const watch = gulp.series(tailwind_build, tailwind_watcher);

exports.dev = dev;
exports.build = build;
exports.watch = watch;