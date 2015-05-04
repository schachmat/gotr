TEX_FILES = $(find -iname '*.tex')
IMG_SRCS = $(wildcard img/*)

all: $(TEX_FILES) $(IMG_SRCS) Makefile
	pdflatex descr.tex && pdflatex descr.tex
clean:
	rm -f *.aux *.bbl *.blg *.log *.pdf *.toc *.nav *.out *.snm *.vrb
