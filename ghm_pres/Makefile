TEX_FILES = $(find -iname '*.tex')
IMG_SRCS = $(wildcard abbildungen/*)

all: $(TEX_FILES) $(IMG_SRCS) Makefile options.tex
	pdflatex gotr.tex && pdflatex gotr.tex
clean:
	rm -f *.aux *.bbl *.blg *.log *.pdf *.toc *.nav *.out *.snm *.vrb
