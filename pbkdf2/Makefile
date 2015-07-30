all: pbkdf2.pdf pbkdf2-notes.pdf

PDFLATEX=pdflatex -interaction=batchmode -halt-on-error

pbkdf2.pdf: pbkdf2.tex
	$(PDFLATEX) -jobname $(@:.pdf=) "\newcommand{\extoptions}{}\input{pbkdf2.tex}"

pbkdf2-notes.pdf: pbkdf2.tex
	$(PDFLATEX) -jobname $(@:.pdf=) "\newcommand{\extoptions}{\setbeameroption{show only notes}}\input{pbkdf2.tex}"

clean:
	rm *.pdf *.log *.nav *.aux
